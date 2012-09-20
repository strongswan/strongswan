/*
 * Copyright (C) 2010 Tobias Brunner
 * Copyright (C) 2008-2010 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#include "mem_pool.h"

#include <debug.h>
#include <utils/hashtable.h>
#include <utils/linked_list.h>
#include <threading/mutex.h>

#define POOL_LIMIT (sizeof(uintptr_t)*8)

typedef struct private_mem_pool_t private_mem_pool_t;

/**
 * private data of mem_pool_t
 */
struct private_mem_pool_t {
	/**
	 * public interface
	 */
	mem_pool_t public;

	/**
	 * name of the pool
	 */
	char *name;

	/**
	 * base address of the pool
	 */
	host_t *base;

	/**
	 * size of the pool
	 */
	u_int size;

	/**
	 * next unused address
	 */
	u_int unused;

	/**
	 * lease hashtable [identity => entry]
	 */
	hashtable_t *leases;

	/**
	 * lock to safely access the pool
	 */
	mutex_t *mutex;
};

/**
 * Lease entry.
 */
typedef struct {
	/* identitiy reference */
	identification_t *id;
	/* list of online leases, as offset */
	linked_list_t *online;
	/* list of offline leases, as offset */
	linked_list_t *offline;
} entry_t;

/**
 * hashtable hash function for identities
 */
static u_int id_hash(identification_t *id)
{
	return chunk_hash(id->get_encoding(id));
}

/**
 * hashtable equals function for identities
 */
static bool id_equals(identification_t *a, identification_t *b)
{
	return a->equals(a, b);
}

/**
 * convert a pool offset to an address
 */
static host_t* offset2host(private_mem_pool_t *pool, int offset)
{
	chunk_t addr;
	host_t *host;
	u_int32_t *pos;

	offset--;
	if (offset > pool->size)
	{
		return NULL;
	}

	addr = chunk_clone(pool->base->get_address(pool->base));
	if (pool->base->get_family(pool->base) == AF_INET6)
	{
		pos = (u_int32_t*)(addr.ptr + 12);
	}
	else
	{
		pos = (u_int32_t*)addr.ptr;
	}
	*pos = htonl(offset + ntohl(*pos));
	host = host_create_from_chunk(pool->base->get_family(pool->base), addr, 0);
	free(addr.ptr);
	return host;
}

/**
 * convert a host to a pool offset
 */
static int host2offset(private_mem_pool_t *pool, host_t *addr)
{
	chunk_t host, base;
	u_int32_t hosti, basei;

	if (addr->get_family(addr) != pool->base->get_family(pool->base))
	{
		return -1;
	}
	host = addr->get_address(addr);
	base = pool->base->get_address(pool->base);
	if (addr->get_family(addr) == AF_INET6)
	{
		/* only look at last /32 block */
		if (!memeq(host.ptr, base.ptr, 12))
		{
			return -1;
		}
		host = chunk_skip(host, 12);
		base = chunk_skip(base, 12);
	}
	hosti = ntohl(*(u_int32_t*)(host.ptr));
	basei = ntohl(*(u_int32_t*)(base.ptr));
	if (hosti > basei + pool->size)
	{
		return -1;
	}
	return hosti - basei + 1;
}

METHOD(mem_pool_t, get_name, const char*,
	private_mem_pool_t *this)
{
	return this->name;
}

METHOD(mem_pool_t, get_base, host_t*,
	private_mem_pool_t *this)
{
	return this->base;
}

METHOD(mem_pool_t, get_size, u_int,
	private_mem_pool_t *this)
{
	return this->size;
}

METHOD(mem_pool_t, get_online, u_int,
	private_mem_pool_t *this)
{
	enumerator_t *enumerator;
	entry_t *entry;
	u_int count = 0;

	this->mutex->lock(this->mutex);
	enumerator = this->leases->create_enumerator(this->leases);
	while (enumerator->enumerate(enumerator, NULL, &entry))
	{
		count += entry->online->get_count(entry->online);
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	return count;
}

METHOD(mem_pool_t, get_offline, u_int,
	private_mem_pool_t *this)
{
	enumerator_t *enumerator;
	entry_t *entry;
	u_int count = 0;

	this->mutex->lock(this->mutex);
	enumerator = this->leases->create_enumerator(this->leases);
	while (enumerator->enumerate(enumerator, NULL, &entry))
	{
		count += entry->offline->get_count(entry->offline);
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	return count;
}

/**
 * Get an existing lease for id
 */
static int get_existing(private_mem_pool_t *this, identification_t *id,
						host_t *requested)
{
	enumerator_t *enumerator;
	uintptr_t current;
	entry_t *entry;
	int offset = 0;

	entry = this->leases->get(this->leases, id);
	if (!entry)
	{
		return 0;
	}

	/* check for a valid offline lease, refresh */
	enumerator = entry->offline->create_enumerator(entry->offline);
	if (enumerator->enumerate(enumerator, &current))
	{
		entry->offline->remove_at(entry->offline, enumerator);
		entry->online->insert_last(entry->online, (void*)current);
		offset = current;
	}
	enumerator->destroy(enumerator);
	if (offset)
	{
		DBG1(DBG_CFG, "reassigning offline lease to '%Y'", id);
		return offset;
	}

	/* check for a valid online lease to reassign */
	enumerator = entry->online->create_enumerator(entry->online);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (current == host2offset(this, requested))
		{
			offset = current;
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (offset)
	{
		DBG1(DBG_CFG, "reassigning online lease to '%Y'", id);
	}
	return offset;
}

/**
 * Get a new lease for id
 */
static int get_new(private_mem_pool_t *this, identification_t *id)
{
	entry_t *entry;
	uintptr_t offset = 0;

	if (this->unused < this->size)
	{
		entry = this->leases->get(this->leases, id);
		if (!entry)
		{
			INIT(entry,
				.id = id->clone(id),
				.online = linked_list_create(),
				.offline = linked_list_create(),
			);
			this->leases->put(this->leases, entry->id, entry);
		}
		/* assigning offset, starting by 1 */
		offset = ++this->unused;
		entry->online->insert_last(entry->online, (void*)offset);
		DBG1(DBG_CFG, "assigning new lease to '%Y'", id);
	}
	return offset;
}

/**
 * Get a reassigned lease for id in case the pool is full
 */
static int get_reassigned(private_mem_pool_t *this, identification_t *id)
{
	enumerator_t *enumerator;
	entry_t *entry;
	uintptr_t current, offset = 0;

	enumerator = this->leases->create_enumerator(this->leases);
	while (enumerator->enumerate(enumerator, NULL, &entry))
	{
		if (entry->offline->remove_first(entry->offline,
										 (void**)&current) == SUCCESS)
		{
			offset = current;
			DBG1(DBG_CFG, "reassigning existing offline lease by '%Y'"
				 " to '%Y'", entry->id, id);
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (offset)
	{
		INIT(entry,
			.id = id->clone(id),
			.online = linked_list_create(),
			.offline = linked_list_create(),
		);
		entry->online->insert_last(entry->online, (void*)offset);
		this->leases->put(this->leases, entry->id, entry);
	}
	return offset;
}

METHOD(mem_pool_t, acquire_address, host_t*,
	private_mem_pool_t *this, identification_t *id, host_t *requested,
	mem_pool_op_t operation)
{
	int offset = 0;

	/* if the pool is empty (e.g. in the %config case) we simply return the
	 * requested address */
	if (this->size == 0)
	{
		return requested->clone(requested);
	}

	if (requested->get_family(requested) !=
		this->base->get_family(this->base))
	{
		return NULL;
	}

	this->mutex->lock(this->mutex);
	switch (operation)
	{
		case MEM_POOL_EXISTING:
			offset = get_existing(this, id, requested);
			break;
		case MEM_POOL_NEW:
			offset = get_new(this, id);
			break;
		case MEM_POOL_REASSIGN:
			offset = get_reassigned(this, id);
			if (!offset)
			{
				DBG1(DBG_CFG, "pool '%s' is full, unable to assign address",
					 this->name);
			}
			break;
		default:
			break;
	}
	this->mutex->unlock(this->mutex);

	if (offset)
	{
		return offset2host(this, offset);
	}
	return NULL;
}

METHOD(mem_pool_t, release_address, bool,
	private_mem_pool_t *this, host_t *address, identification_t *id)
{
	bool found = FALSE;
	entry_t *entry;
	uintptr_t offset;

	if (this->size != 0)
	{
		this->mutex->lock(this->mutex);
		entry = this->leases->get(this->leases, id);
		if (entry)
		{
			offset = host2offset(this, address);
			if (entry->online->remove(entry->online, (void*)offset, NULL) > 0)
			{
				DBG1(DBG_CFG, "lease %H by '%Y' went offline", address, id);
				entry->offline->insert_last(entry->offline, (void*)offset);
				found = TRUE;
			}
		}
		this->mutex->unlock(this->mutex);
	}
	return found;
}

/**
 * lease enumerator
 */
typedef struct {
	/** implemented enumerator interface */
	enumerator_t public;
	/** hash-table enumerator */
	enumerator_t *entries;
	/** online enumerator */
	enumerator_t *online;
	/** offline enumerator */
	enumerator_t *offline;
	/** enumerated pool */
	private_mem_pool_t *pool;
	/** currently enumerated entry */
	entry_t *entry;
	/** currently enumerated lease address */
	host_t *addr;
} lease_enumerator_t;

METHOD(enumerator_t, lease_enumerate, bool,
	lease_enumerator_t *this, identification_t **id, host_t **addr, bool *online)
{
	uintptr_t offset;

	DESTROY_IF(this->addr);
	this->addr = NULL;

	while (TRUE)
	{
		if (this->entry)
		{
			if (this->online->enumerate(this->online, (void**)&offset))
			{
				*id = this->entry->id;
				*addr = this->addr = offset2host(this->pool, offset);
				*online = TRUE;
				return TRUE;
			}
			if (this->offline->enumerate(this->offline, (void**)&offset))
			{
				*id = this->entry->id;
				*addr = this->addr = offset2host(this->pool, offset);
				*online = FALSE;
				return TRUE;
			}
			this->online->destroy(this->online);
			this->offline->destroy(this->offline);
			this->online = this->offline = NULL;
		}
		if (!this->entries->enumerate(this->entries, NULL, &this->entry))
		{
			return FALSE;
		}
		this->online = this->entry->online->create_enumerator(
														this->entry->online);
		this->offline = this->entry->offline->create_enumerator(
														this->entry->offline);
	}
}

METHOD(enumerator_t, lease_enumerator_destroy, void,
	lease_enumerator_t *this)
{
	DESTROY_IF(this->addr);
	DESTROY_IF(this->online);
	DESTROY_IF(this->offline);
	this->entries->destroy(this->entries);
	this->pool->mutex->unlock(this->pool->mutex);
	free(this);
}

METHOD(mem_pool_t, create_lease_enumerator, enumerator_t*,
	   private_mem_pool_t *this)
{
	lease_enumerator_t *enumerator;

	this->mutex->lock(this->mutex);
	INIT(enumerator,
		.public = {
			.enumerate = (void*)_lease_enumerate,
			.destroy = _lease_enumerator_destroy,
		},
		.pool = this,
		.entries = this->leases->create_enumerator(this->leases),
	);
	return &enumerator->public;
}

METHOD(mem_pool_t, destroy, void,
	private_mem_pool_t *this)
{
	enumerator_t *enumerator;
	entry_t *entry;

	enumerator = this->leases->create_enumerator(this->leases);
	while (enumerator->enumerate(enumerator, NULL, &entry))
	{
		entry->id->destroy(entry->id);
		entry->online->destroy(entry->online);
		entry->offline->destroy(entry->offline);
		free(entry);
	}
	enumerator->destroy(enumerator);

	this->leases->destroy(this->leases);
	this->mutex->destroy(this->mutex);
	DESTROY_IF(this->base);
	free(this->name);
	free(this);
}

/**
 * Described in header
 */
mem_pool_t *mem_pool_create(char *name, host_t *base, int bits)
{
	private_mem_pool_t *this;
	int addr_bits;

	INIT(this,
		.public = {
			.get_name = _get_name,
			.get_base = _get_base,
			.get_size = _get_size,
			.get_online = _get_online,
			.get_offline = _get_offline,
			.acquire_address = _acquire_address,
			.release_address = _release_address,
			.create_lease_enumerator = _create_lease_enumerator,
			.destroy = _destroy,
		},
		.name = strdup(name),
		.leases = hashtable_create((hashtable_hash_t)id_hash,
								   (hashtable_equals_t)id_equals, 16),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	if (base)
	{
		addr_bits = base->get_family(base) == AF_INET ? 32 : 128;
		bits = max(0, min(bits, base->get_family(base) == AF_INET ? 32 : 128));
		/* net bits -> host bits */
		bits = addr_bits - bits;
		if (bits > POOL_LIMIT)
		{
			bits = POOL_LIMIT;
			DBG1(DBG_CFG, "virtual IP pool too large, limiting to %H/%d",
				 base, addr_bits - bits);
		}
		this->size = 1 << (bits);

		if (this->size > 2)
		{	/* do not use first and last addresses of a block */
			this->unused++;
			this->size -= 2;
		}
		this->base = base->clone(base);
	}

	return &this->public;
}

