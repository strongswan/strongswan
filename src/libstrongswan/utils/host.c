/**
 * @file host.c
 * 
 * @brief Implementation of host_t.
 * 
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include <string.h>

#include "host.h"


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
	 * string representation of host
	 */
	char *string;
	
	/**
	 * low-lewel structure, wich stores the address
	 */
	union {
		struct sockaddr address;
		struct sockaddr_in address4;
	};
	/**
	 * length of address structure
	 */
	socklen_t socklen;
};


/**
 * implements host_t.get_sockaddr
 */
static sockaddr_t *get_sockaddr(private_host_t *this)
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
 * Implementation of host_t.is_anyaddr.
 */
static bool is_anyaddr(private_host_t *this)
{
	switch (this->family) 
	{
		case AF_INET: 
		{
			static u_int8_t default_route[4] = {0x00, 0x00, 0x00, 0x00};
			
			return !memcmp(default_route, &(this->address4.sin_addr.s_addr), 4);
		}
		default:
		{
			/* empty chunk is returned */
			return FALSE;
		}	
	}
}

/**
 * implements host_t.get_string
 */
static char *get_string(private_host_t *this)
{
	switch (this->family) 
	{
		case AF_INET: 
		{
			char *string;
			/* we need to clone it, since inet_ntoa overwrites 
			 * internal buffer on subsequent calls
			 */
			if (this->string == NULL)
			{
				string = is_anyaddr(this)? "%any" : inet_ntoa(this->address4.sin_addr);
				this->string = malloc(strlen(string)+1);
				strcpy(this->string, string);
			}
			return this->string;
		}
		default:
		{
			return "(family	not supported)";
		}
	}
}

/**
 * Implementation of host_t.get_address.
 */
static chunk_t get_address(private_host_t *this)
{
	chunk_t address = CHUNK_INITIALIZER;
	
	switch (this->family) 
	{
		case AF_INET: 
		{
			/* allocate 4 bytes for IPv4 address*/
			address.ptr = (char*)&(this->address4.sin_addr.s_addr);
			address.len = 4;
		}
		default:
		{
			/* empty chunk is returned */
			return address;
		}
	}
}

/**
 * implements host_t.get_family
 */
static int get_family(private_host_t *this)
{
	return this->family;	
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
			return ntohs(this->address4.sin_port);
		}
		default:
		{
			return 0;
		}
	}
}

/**
 * implements host_t.set_port
 */
static void set_port(private_host_t *this, u_int16_t port)
{
	switch (this->family)
	{
		case AF_INET:
		{
			this->address4.sin_port = htons(port);
		}
		default:
		{
			/*TODO*/
		}
	}
}

/**
 * Implements host_t.clone.
 */
static private_host_t *clone(private_host_t *this)
{
	private_host_t *new = malloc_thing(private_host_t);
	
		
	memcpy(new, this, sizeof(private_host_t));
	if (this->string)
	{
		new->string = malloc(strlen(this->string)+1);
		strcpy(new->string, this->string);
	}
	return new;
}

/**
 * Impelements host_t.ip_equals
 */
static bool ip_equals(private_host_t *this, private_host_t *other)
{
	switch (this->family)
	{
		/* IPv4 */
		case AF_INET:
		{
			if ((this->address4.sin_family == other->address4.sin_family) &&
				(this->address4.sin_addr.s_addr == other->address4.sin_addr.s_addr))
			{
				return TRUE;	
			}
		}
	}
	return FALSE;
}

/**
 * Implements host_t.get_differences
 */
static host_diff_t get_differences(private_host_t *this, private_host_t *other)
{
	host_diff_t ret = HOST_DIFF_NONE;
	
	if (!this->public.ip_equals(&this->public, &other->public))
	{
		ret |= HOST_DIFF_ADDR;
	}

	if (this->public.get_port(&this->public) != other->public.get_port(&other->public))
	{
		ret |= HOST_DIFF_PORT;
	}

	return ret;
}

/**
 * Impelements host_t.equals
 */
static bool equals(private_host_t *this, private_host_t *other)
{
	switch (this->family)
	{
		/* IPv4 */
		case AF_INET:
		{
			if ((this->address4.sin_family == other->address4.sin_family) &&
				(this->address4.sin_addr.s_addr == other->address4.sin_addr.s_addr) &&
				(this->address4.sin_port == other->address4.sin_port))
			{
				return TRUE;	
			}
		}
	}
	return FALSE;
}

/**
 * Implements host_t.destroy
 */
static void destroy(private_host_t *this)
{
	free(this->string);
	free(this);
}

/**
 * Creates an empty host_t object 
 */
static private_host_t *host_create_empty(void)
{
	private_host_t *this = malloc_thing(private_host_t);
	
	this->public.get_sockaddr = (sockaddr_t* (*) (host_t*))get_sockaddr;
	this->public.get_sockaddr_len = (socklen_t*(*) (host_t*))get_sockaddr_len;
	this->public.clone = (host_t* (*) (host_t*))clone;
	this->public.get_family = (int (*) (host_t*))get_family;
	this->public.get_string = (char* (*) (host_t *))get_string;
	this->public.get_address = (chunk_t (*) (host_t *)) get_address;
	this->public.get_port = (u_int16_t (*) (host_t *))get_port;
	this->public.set_port = (void (*) (host_t *,u_int16_t))set_port;
	this->public.get_differences = (host_diff_t (*) (host_t *,host_t *)) get_differences;
	this->public.ip_equals = (bool (*) (host_t *,host_t *)) ip_equals;
	this->public.equals = (bool (*) (host_t *,host_t *)) equals;
	this->public.is_anyaddr = (bool (*) (host_t *)) is_anyaddr;
	this->public.destroy = (void (*) (host_t*))destroy;
	
	this->string = NULL;
	
	return this;
}

/*
 * Described in header.
 */
host_t *host_create(int family, char *address, u_int16_t port)
{
	private_host_t *this = host_create_empty();
	
	this->family = family;

	switch (family)
	{
		/* IPv4 */
		case AF_INET:
		{
			this->address4.sin_family = AF_INET;
			this->address4.sin_addr.s_addr = inet_addr(address);
			this->address4.sin_port = htons(port);
			this->socklen = sizeof(struct sockaddr_in);
			return &(this->public);
		}
		default:
		{
			free(this);
			return NULL;

		}
	}
	
}

/*
 * Described in header.
 */
host_t *host_create_from_hdr(u_long address, u_short port)
{
	private_host_t *this = host_create_empty();
	
	this->family = AF_INET;

	this->address4.sin_family = AF_INET;
	this->address4.sin_addr.s_addr = address;
	this->address4.sin_port = port;
	this->socklen = sizeof(struct sockaddr_in);
	return &(this->public);
}

/*
 * Described in header.
 */
host_t *host_create_from_chunk(int family, chunk_t address, u_int16_t port)
{
	private_host_t *this = host_create_empty();
	
	this->family = family;
	switch (family)
	{
		/* IPv4 */
		case AF_INET:
		{
			if (address.len != 4)
			{
				break;	
			}
			this->address4.sin_family = AF_INET;
			memcpy(&(this->address4.sin_addr.s_addr),address.ptr,4);
			this->address4.sin_port = htons(port);
			this->socklen = sizeof(struct sockaddr_in);
			return &(this->public);
		}
	}
	free(this);
	return NULL;
}

/*
 * Described in header.
 */
host_t *host_create_from_sockaddr(sockaddr_t *sockaddr)
{
	chunk_t address;
	
	switch (sockaddr->sa_family)
	{
		/* IPv4 */
		case AF_INET:
		{
			struct sockaddr_in *sin = (struct sockaddr_in *)sockaddr;
			address.ptr = (void*)&(sin->sin_addr.s_addr);
			address.len = 4;
			return host_create_from_chunk(AF_INET, address, ntohs(sin->sin_port));
		}
		default:
			return NULL;
	}
}

