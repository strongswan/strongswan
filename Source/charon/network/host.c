/**
 * @file host.c
 * 
 * @brief host object, identifies a host and defines some useful functions on it.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include "host.h"

#include <utils/allocator.h>


typedef struct private_host_t private_host_t;

/**
 * @brief Private Data of a host object.
 */
struct private_host_t { 	
	/**
	 * Public data
	 */
	host_t public;
	
	/**
	 * Address family to use, such as AF_INET or AF_INET6
	 */
	int family;
	
	/**
	 * low-lewel structure, wich stores the address
	 */
	sockaddr_t address;
	
	/**
	 * length of address structure
	 */
	socklen_t socklen;
};


/**
 * implements host_t.get_sockaddr
 */
static sockaddr_t  *get_sockaddr(private_host_t *this)
{
	return &(this->address);
}

/**
 * implements host_t.get_sockaddr_len
 */
static socklen_t *get_sockaddr_len(private_host_t *this)
{
	return &(this->socklen);
}

/**
 * implements host_t.get_address
 */
static char *get_address(private_host_t *this)
{
	switch (this->family) 
	{
		case AF_INET: 
		{
			struct sockaddr_in *sin = (struct sockaddr_in*)&(this->address);
			return inet_ntoa(sin->sin_addr);
		}
		default:
		{
			return "(family	not supported)";
		}
	}
}

/**
 * implements host_t.get_port
 */
static u_int16_t get_port(private_host_t *this)
{
	switch (this->family) 
	{
		case AF_INET: 
		{
			struct sockaddr_in *sin = (struct sockaddr_in*)&(this->address);
			return ntohs(sin->sin_port);
		}
		default:
		{
			return 0;
		}
	}
}

/**
 * Implements host_t.destroy
 */
static status_t destroy(private_host_t *this)
{
	allocator_free(this);
	return SUCCESS;
}

/**
 * Implements host_t.clone.
 */
static status_t clone(private_host_t *this, host_t **other)
{
	private_host_t *new = allocator_alloc_thing(private_host_t);
	
	if (new == NULL)
	{
		return OUT_OF_RES;	
	}	
		
	memcpy(new, this, sizeof(private_host_t));
	*other = (host_t*)new;
	
	return SUCCESS;
}


/*
 * see header
 */
host_t *host_create(int family, char *address, u_int16_t port)
{
	private_host_t *this = allocator_alloc_thing(private_host_t);
	if (this == NULL)
	{
		return NULL;	
	}
	
	this->public.get_sockaddr = (sockaddr_t* (*) (host_t*))get_sockaddr;
	this->public.get_sockaddr_len = (socklen_t*(*) (host_t*))get_sockaddr_len;
	this->public.clone = (status_t (*) (host_t*, host_t**))clone;
	this->public.get_address = (char* (*) (host_t *))get_address;
	this->public.get_port = (u_int16_t (*) (host_t *))get_port;
	this->public.destroy = (status_t (*) (host_t*))destroy;
	
	this->family = family;

	switch (family)
	{
		/* IPv4 */
		case AF_INET:
		{
			struct sockaddr_in *sin = (struct sockaddr_in*)&(this->address);
			sin->sin_family = AF_INET;
			sin->sin_addr.s_addr = inet_addr(address);
			sin->sin_port = htons(port);
			this->socklen = sizeof(struct sockaddr_in);
			return (host_t*)this;
		}
	}
	allocator_free(this);
	return NULL;
}
