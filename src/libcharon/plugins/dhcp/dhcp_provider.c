/*
 * Copyright (C) 2025 Tobias Brunner
 * Copyright (C) 2010 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "dhcp_provider.h"

#include <collections/hashtable.h>
#include <threading/mutex.h>

typedef struct private_dhcp_provider_t private_dhcp_provider_t;

/**
 * Private data of an dhcp_provider_t object.
 */
struct private_dhcp_provider_t {

	/**
	 * Public dhcp_provider_t interface.
	 */
	dhcp_provider_t public;

	/**
	 * Completed DHCP transactions/leases
	 */
	hashtable_t *transactions;

	/**
	 * Lock for transactions/leases
	 */
	mutex_t *mutex;

	/**
	 * DHCP communication socket
	 */
	dhcp_socket_t *socket;
};

/**
 * Entry to keep track of leases/DHCP transactions
 */
typedef struct {
	/* Latest transaction */
	dhcp_transaction_t *transaction;
	/* Cached identity from the latest transaction (internal data) */
	identification_t *id;
	/* Cached address from the latest transaction (internal data) */
	host_t *addr;
	/* Reference counter */
	u_int refs;
} entry_t;

/**
 * Hash an entry
 */
static u_int hash(const void *key)
{
	const entry_t *entry = (const entry_t*)key;
	return entry->id->hash(entry->id,
						   chunk_hash(entry->addr->get_address(entry->addr)));
}

/**
 * Compare two entries
 */
static bool equals(const void *a, const void *b)
{
	const entry_t *entry_a = (const entry_t*)a;
	const entry_t *entry_b = (const entry_t*)b;
	return entry_a->addr->ip_equals(entry_a->addr, entry_b->addr) &&
		   entry_a->id->equals(entry_a->id, entry_b->id);
}

METHOD(attribute_provider_t, acquire_address, host_t*,
	private_dhcp_provider_t *this, linked_list_t *pools,
	ike_sa_t *ike_sa, host_t *requested)
{
	dhcp_transaction_t *transaction;
	identification_t *id;
	host_t *vip = NULL;
	entry_t lookup, *entry;

	if (requested->get_family(requested) != AF_INET ||
		!pools->find_first(pools, linked_list_match_str, NULL, "dhcp"))
	{
		return NULL;
	}
	id = ike_sa->get_other_eap_id(ike_sa);
	transaction = this->socket->enroll(this->socket, id);
	if (!transaction)
	{
		return NULL;
	}
	lookup.id = transaction->get_identity(transaction);
	lookup.addr = transaction->get_address(transaction);
	vip = lookup.addr->clone(lookup.addr);

	this->mutex->lock(this->mutex);
	entry = this->transactions->get(this->transactions, &lookup);
	if (!entry)
	{
		INIT(entry,
			.transaction = transaction,
			.addr = lookup.addr,
			.id = lookup.id,
		);
		this->transactions->put(this->transactions, entry, entry);
	}
	else
	{
		/* always store the latest transaction, update cached data */
		entry->transaction->destroy(entry->transaction);
		entry->transaction = transaction;
		entry->addr = lookup.addr;
		entry->id = lookup.id;
	}
	entry->refs++;
	this->mutex->unlock(this->mutex);
	return vip;
}

METHOD(attribute_provider_t, release_address, bool,
	private_dhcp_provider_t *this, linked_list_t *pools,
	host_t *address, ike_sa_t *ike_sa)
{
	entry_t lookup, *entry = NULL;
	bool release = FALSE;

	if (address->get_family(address) != AF_INET ||
		!pools->find_first(pools, linked_list_match_str, NULL, "dhcp"))
	{
		return FALSE;
	}
	lookup.id = ike_sa->get_other_eap_id(ike_sa);
	lookup.addr = address;

	this->mutex->lock(this->mutex);
	entry = this->transactions->get(this->transactions, &lookup);
	if (entry && --entry->refs == 0)
	{
		this->transactions->remove(this->transactions, entry);
		release = TRUE;
	}
	this->mutex->unlock(this->mutex);

	if (release)
	{
		this->socket->release(this->socket, entry->transaction);
		entry->transaction->destroy(entry->transaction);
		free(entry);
	}
	return entry != NULL;
}

METHOD(attribute_provider_t, create_attribute_enumerator, enumerator_t*,
	private_dhcp_provider_t *this, linked_list_t *pools, ike_sa_t *ike_sa,
	linked_list_t *vips)
{
	entry_t lookup, *entry = NULL;
	enumerator_t *enumerator;
	host_t *vip;

	if (!pools->find_first(pools, linked_list_match_str, NULL, "dhcp"))
	{
		return NULL;
	}

	lookup.id = ike_sa->get_other_eap_id(ike_sa);
	this->mutex->lock(this->mutex);
	enumerator = vips->create_enumerator(vips);
	while (enumerator->enumerate(enumerator, &vip))
	{
		lookup.addr = vip;
		entry = this->transactions->get(this->transactions, &lookup);
		if (entry)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!entry)
	{
		this->mutex->unlock(this->mutex);
		return NULL;
	}
	return enumerator_create_cleaner(
			entry->transaction->create_attribute_enumerator(entry->transaction),
			(void*)this->mutex->unlock, this->mutex);
}

METHOD(dhcp_provider_t, destroy, void,
	private_dhcp_provider_t *this)
{
	enumerator_t *enumerator;
	entry_t *entry;

	enumerator = this->transactions->create_enumerator(this->transactions);
	while (enumerator->enumerate(enumerator, NULL, &entry))
	{
		entry->transaction->destroy(entry->transaction);
		free(entry);
	}
	enumerator->destroy(enumerator);
	this->transactions->destroy(this->transactions);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
dhcp_provider_t *dhcp_provider_create(dhcp_socket_t *socket)
{
	private_dhcp_provider_t *this;

	INIT(this,
		.public = {
			.provider = {
				.acquire_address = _acquire_address,
				.release_address = _release_address,
				.create_attribute_enumerator = _create_attribute_enumerator,
			},
			.destroy = _destroy,
		},
		.socket = socket,
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.transactions = hashtable_create(hash, equals, 8),
	);

	return &this->public;
}
