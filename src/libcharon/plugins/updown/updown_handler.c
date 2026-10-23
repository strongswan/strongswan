/*
 * Copyright (C) 2012 Martin Willi
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

#include "updown_handler.h"

#include <daemon.h>
#include <collections/linked_list.h>
#include <threading/rwlock.h>

typedef struct private_updown_handler_t private_updown_handler_t;

/**
 * Private data of an updown_handler_t object.
 */
struct private_updown_handler_t {

	/**
	 * Public updown_handler_t interface.
	 */
	updown_handler_t public;

	/**
	 * List of connection specific attributes, as attributes_t
	 */
	linked_list_t *attrs;

	/**
	 * rwlock to lock access to pools
	 */
	rwlock_t *lock;
};

/**
 * Attributes assigned to an IKE_SA
 */
typedef struct {
	/** unique IKE_SA identifier */
	u_int id;
	/** list of DNS server attributes, as host_t */
	linked_list_t *dns;
	/** list of DNS search domains, as char* */
	linked_list_t *domains;
} attributes_t;

/**
 * Destroy an attributes_t entry
 */
static void attributes_destroy(attributes_t *this)
{
	this->dns->destroy_offset(this->dns, offsetof(host_t, destroy));
	this->domains->destroy_function(this->domains, free);
	free(this);
}

/**
 * Convert a received DNS domain attribute to a sanitized, NUL-terminated
 * string. The value is responder-controlled and ends up in the updown
 * script's environment, so replace any non-printable bytes.
 */
static char *sanitize_domain(chunk_t data)
{
	chunk_t sane;
	char *domain;

	chunk_printable(data, &sane, '?');
	domain = strndup(sane.ptr, sane.len);
	chunk_free(&sane);
	return domain;
}

METHOD(attribute_handler_t, handle, bool,
	private_updown_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	attributes_t *current, *attr = NULL;
	enumerator_t *enumerator;
	host_t *host = NULL;
	char *domain = NULL;

	switch (type)
	{
		case INTERNAL_IP4_DNS:
			host = host_create_from_chunk(AF_INET, data, 0);
			break;
		case INTERNAL_IP6_DNS:
			host = host_create_from_chunk(AF_INET6, data, 0);
			break;
		case INTERNAL_DNS_DOMAIN:
			if (data.len)
			{
				domain = sanitize_domain(data);
			}
			break;
		default:
			return FALSE;
	}
	if (!host && !domain)
	{
		return FALSE;
	}

	this->lock->write_lock(this->lock);
	enumerator = this->attrs->create_enumerator(this->attrs);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (current->id == ike_sa->get_unique_id(ike_sa))
		{
			attr = current;
		}
	}
	enumerator->destroy(enumerator);

	if (!attr)
	{
		INIT(attr,
			.id = ike_sa->get_unique_id(ike_sa),
			.dns = linked_list_create(),
			.domains = linked_list_create(),
		);
		this->attrs->insert_last(this->attrs, attr);
	}
	if (host)
	{
		attr->dns->insert_last(attr->dns, host);
	}
	else
	{
		attr->domains->insert_last(attr->domains, domain);
	}
	this->lock->unlock(this->lock);

	return TRUE;
}

METHOD(attribute_handler_t, release, void,
	private_updown_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	attributes_t *attr;
	enumerator_t *enumerator, *servers, *domains;
	host_t *host;
	char *domain, *sane = NULL;
	bool found = FALSE;
	int family = AF_UNSPEC;

	switch (type)
	{
		case INTERNAL_IP4_DNS:
			family = AF_INET;
			break;
		case INTERNAL_IP6_DNS:
			family = AF_INET6;
			break;
		case INTERNAL_DNS_DOMAIN:
			sane = sanitize_domain(data);
			break;
		default:
			return;
	}

	this->lock->write_lock(this->lock);
	enumerator = this->attrs->create_enumerator(this->attrs);
	while (enumerator->enumerate(enumerator, &attr))
	{
		if (attr->id == ike_sa->get_unique_id(ike_sa))
		{
			if (sane)
			{
				domains = attr->domains->create_enumerator(attr->domains);
				while (domains->enumerate(domains, &domain))
				{
					if (streq(domain, sane))
					{
						attr->domains->remove_at(attr->domains, domains);
						free(domain);
						found = TRUE;
						break;
					}
				}
				domains->destroy(domains);
			}
			else
			{
				servers = attr->dns->create_enumerator(attr->dns);
				while (servers->enumerate(servers, &host))
				{
					if (host->get_family(host) == family &&
						chunk_equals(data, host->get_address(host)))
					{
						attr->dns->remove_at(attr->dns, servers);
						host->destroy(host);
						found = TRUE;
						break;
					}
				}
				servers->destroy(servers);
			}
			if (attr->dns->get_count(attr->dns) == 0 &&
				attr->domains->get_count(attr->domains) == 0)
			{
				this->attrs->remove_at(this->attrs, enumerator);
				attributes_destroy(attr);
				break;
			}
		}
		if (found)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	free(sane);
}

/**
 * Create an enumerator over the DNS servers (host_t) or search domains (char*)
 * of the current IKE_SA. Holds the read lock until the enumerator is destroyed.
 */
static enumerator_t *create_enumerator(private_updown_handler_t *this,
									   bool domains)
{
	attributes_t *attr;
	enumerator_t *enumerator;
	linked_list_t *list;
	ike_sa_t *ike_sa;

	ike_sa = charon->bus->get_sa(charon->bus);
	if (!ike_sa)
	{
		return enumerator_create_empty();
	}

	this->lock->read_lock(this->lock);
	enumerator = this->attrs->create_enumerator(this->attrs);
	while (enumerator->enumerate(enumerator, &attr))
	{
		if (attr->id == ike_sa->get_unique_id(ike_sa))
		{
			list = domains ? attr->domains : attr->dns;
			enumerator->destroy(enumerator);
			return enumerator_create_cleaner(list->create_enumerator(list),
										(void*)this->lock->unlock, this->lock);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	return enumerator_create_empty();
}

METHOD(updown_handler_t, create_dns_enumerator, enumerator_t*,
	private_updown_handler_t *this, u_int id)
{
	return create_enumerator(this, FALSE);
}

METHOD(updown_handler_t, create_domain_enumerator, enumerator_t*,
	private_updown_handler_t *this, u_int id)
{
	return create_enumerator(this, TRUE);
}

METHOD(updown_handler_t, destroy, void,
	private_updown_handler_t *this)
{
	this->lock->destroy(this->lock);
	this->attrs->destroy_function(this->attrs, (void*)attributes_destroy);
	free(this);
}

/**
 * See header
 */
updown_handler_t *updown_handler_create()
{
	private_updown_handler_t *this;

	INIT(this,
		.public = {
			.handler = {
				.handle = _handle,
				.release = _release,
				.create_attribute_enumerator = (void*)enumerator_create_empty,
			},
			.create_dns_enumerator = _create_dns_enumerator,
			.create_domain_enumerator = _create_domain_enumerator,
			.destroy = _destroy,
		},
		.attrs = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}
