/**
 * @file interfaces.c
 *
 * @brief Implementation of interfaces_t.
 *
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
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

#include <net/if.h>
#include <ifaddrs.h>
#include <string.h>

#include "interfaces.h"

typedef struct private_interfaces_t private_interfaces_t;

/**
 * Private data of an interfaces_t object.
 */
struct private_interfaces_t {
	
	/**
	 * Public part of a interfaces_t object.
	 */
	interfaces_t public;

	/**
	 * port that gets added to the host_t obbjects
	 */
	u_int16_t port;
	
	/**
	 * list of addresses
	 */
	linked_list_t *addresses;
};

/**
 * Implements interfaces_t.create_address_iterator
 */
static iterator_t* create_address_iterator(private_interfaces_t *this)
{
	return this->addresses->create_iterator(this->addresses, TRUE);
}
	
/**
 * Implements interfaces_t.is_local_address
 */
static bool is_local_address(private_interfaces_t *this, host_t *host)
{
	iterator_t *iterator;
	host_t *lhost;

	if (host->is_anyaddr(host)) 
	{
		return FALSE;
	}
	
	iterator = this->addresses->create_iterator(this->addresses, TRUE);
	while (iterator->iterate(iterator, (void**)&lhost))
	{
		if (host->get_family(host) == lhost->get_family(lhost) && 
			streq(host->get_address(host), lhost->get_address(lhost)))
		{
			iterator->destroy(iterator);
			return TRUE;
		}
	}

	iterator->destroy(iterator);
	return FALSE;
}

/**
 * Implements interfaces_t.destroy.
 */
static void destroy(private_interfaces_t *this)
{
	host_t *host;
	while (this->addresses->remove_last(this->addresses, (void**)&host) == SUCCESS)
	{
		host->destroy(host);
	}
	this->addresses->destroy(this->addresses);
	free(this);
}

static status_t initialize(private_interfaces_t *this)
{
	struct ifaddrs *list;
	struct ifaddrs *cur;
	host_t *host;

	if (getifaddrs(&list) < 0)
	{
		return FAILED;
	}

	for (cur = list; cur != NULL; cur = cur->ifa_next)
	{
		if (!(cur->ifa_flags & IFF_UP))
			continue;
		
		if (cur->ifa_addr == NULL || cur->ifa_addr->sa_family != AF_INET)
			continue;

		host = host_create_from_sockaddr(cur->ifa_addr);
		if (host) {
			host->set_port(host, this->port);
			this->addresses->insert_last(this->addresses, (void*) host);
		}
	}

	freeifaddrs(list);
	return SUCCESS;
}

/*
 * Documented in header
 */
interfaces_t *interfaces_create(u_int16_t port)
{
	private_interfaces_t *this = malloc_thing(private_interfaces_t);

	this->port = port;
	
	this->public.create_address_iterator = (iterator_t* (*) (interfaces_t*)) create_address_iterator;
	this->public.is_local_address = (bool (*) (interfaces_t*, host_t*)) is_local_address;
	this->public.destroy = (void (*) (interfaces_t*)) destroy;

	this->addresses = linked_list_create();

	if (initialize(this) != SUCCESS)
	{
		destroy(this);
		return NULL;
	}

	return &this->public;
}
