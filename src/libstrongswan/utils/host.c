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
	 * string representation of host
	 */
	char *string;
	
	/**
	 * low-lewel structure, wich stores the address
	 */
	union {
		/** generic type */
		struct sockaddr address;
		/** maximux sockaddr size */
		struct sockaddr_storage address_max;
		/** IPv4 address */
		struct sockaddr_in address4;
		/** IPv6 address */
		struct sockaddr_in6 address6;
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
	switch (this->address.sa_family) 
	{
		case AF_INET:
		{
			u_int8_t default_route[4];
			memset(default_route, 0, sizeof(default_route));
			return memeq(default_route, &(this->address4.sin_addr.s_addr),
						 sizeof(default_route));
		}
		case AF_INET6:
		{
			u_int8_t default_route[16];
			memset(default_route, 0, sizeof(default_route));
			return memeq(default_route, &(this->address6.sin6_addr.s6_addr),
						 sizeof(default_route));
		}
		default:
		{
			return FALSE;
		}	
	}
}

/**
 * implements host_t.get_string
 */
static char *get_string(private_host_t *this)
{
	return this->string;
}

/**
 * Compute the string value
 */
static void set_string(private_host_t *this)
{
	if (is_anyaddr(this))
	{
		this->string = strdup("%any");
		return;
	}
	
	switch (this->address.sa_family) 
	{
		case AF_INET:
		case AF_INET6:
		{
			char buffer[INET6_ADDRSTRLEN];
			void *address;
			
			if (this->address.sa_family == AF_INET)
			{
				address = &this->address4.sin_addr;
			}
			else
			{
				address = &this->address6.sin6_addr;
			}
			
			if (inet_ntop(this->address.sa_family, address,
						  buffer, sizeof(buffer)) != NULL)
			{
				this->string = strdup(buffer);
			}
			else
			{
				this->string = strdup("(address conversion failed)");
			}
			return;
		}
		default:
		{
			this->string = strdup("(family not supported)");
		}
	}
}

/**
 * Implementation of host_t.get_address.
 */
static chunk_t get_address(private_host_t *this)
{
	chunk_t address = CHUNK_INITIALIZER;
	
	switch (this->address.sa_family) 
	{
		case AF_INET:
		{
			address.ptr = (char*)&(this->address4.sin_addr.s_addr);
			address.len = 4;
			return address;
		}
		case AF_INET6:
		{
			address.ptr = (char*)&(this->address6.sin6_addr.s6_addr);
			address.len = 16;
			return address;
		}
		default:
		{
			/* return empty chunk */
			return address;
		}
	}
}

/**
 * implements host_t.get_family
 */
static int get_family(private_host_t *this)
{
	return this->address.sa_family;
}

/**
 * implements host_t.get_port
 */
static u_int16_t get_port(private_host_t *this)
{
	switch (this->address.sa_family) 
	{
		case AF_INET:
		{
			return ntohs(this->address4.sin_port);
		}
		case AF_INET6:
		{
			return ntohs(this->address6.sin6_port);
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
	switch (this->address.sa_family)
	{
		case AF_INET:
		{
			this->address4.sin_port = htons(port);
			break;
		}
		case AF_INET6:
		{
			this->address6.sin6_port = htons(port);
			break;
		}
		default:
		{
			break;
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
		new->string = strdup(this->string);
	}
	return new;
}

/**
 * Impelements host_t.ip_equals
 */
static bool ip_equals(private_host_t *this, private_host_t *other)
{
	if (this->address.sa_family != other->address.sa_family)
	{
		/* 0.0.0.0 and ::0 are equal */
		if (is_anyaddr(this) && is_anyaddr(other))
		{
			return TRUE;
		}
		
		return FALSE;
	}
	
	switch (this->address.sa_family)
	{
		case AF_INET:
		{
			if (memeq(&this->address4.sin_addr, &other->address4.sin_addr,
					  sizeof(this->address4.sin_addr)))
			{
				return TRUE;
			}
			break;
		}
		case AF_INET6:
		{
			if (memeq(&this->address6.sin6_addr, &other->address6.sin6_addr,
					  sizeof(this->address6.sin6_addr)))
			{
				return TRUE;
			}
		}
		default:
			break;
	}
	return FALSE;
}

/**
 * Implements host_t.get_differences
 */
static host_diff_t get_differences(host_t *this, host_t *other)
{
	host_diff_t ret = HOST_DIFF_NONE;
	
	if (!this->ip_equals(this, other))
	{
		ret |= HOST_DIFF_ADDR;
	}

	if (this->get_port(this) != other->get_port(other))
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
	if (!ip_equals(this, other))
	{
		return FAILED;
	}
	
	switch (this->address.sa_family)
	{
		case AF_INET:
		{
			if (this->address4.sin_port == other->address4.sin_port)
			{
				return TRUE;
			}
			break;
		}
		case AF_INET6:
		{
			if (this->address6.sin6_port == other->address6.sin6_port)
			{
				return TRUE;
			}
			break;
		}
		default:
			break;
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
	this->public.get_differences = get_differences;
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
	
	this->address.sa_family = family;

	switch (family)
	{
		case AF_INET:
		{
			if (inet_pton(family, address, &this->address4.sin_addr) <=0)
			{
				break;
			}
			this->address4.sin_port = htons(port);
			this->socklen = sizeof(struct sockaddr_in);
			set_string(this);
			return &this->public;
		}
		case AF_INET6:
		{
			if (inet_pton(family, address, &this->address6.sin6_addr) <=0)
			{
				break;
			}
			this->address6.sin6_port = htons(port);
			this->socklen = sizeof(struct sockaddr_in6);
			set_string(this);
			return &this->public;
		}
		default:
		{
			break;
		}
	}
	free(this);
	return NULL;
}

/*
 * Described in header.
 */
host_t *host_create_from_string(char *string, u_int16_t port)
{
	private_host_t *this = host_create_empty();
	
	if (strchr(string, '.'))
	{
		this->address.sa_family = AF_INET;
	}
	else
	{
		this->address.sa_family = AF_INET6;
	}

	switch (this->address.sa_family)
	{
		case AF_INET:
		{
			if (inet_pton(AF_INET, string, &this->address4.sin_addr) <=0)
			{
				break;
			}
			this->address4.sin_port = htons(port);
			this->socklen = sizeof(struct sockaddr_in);
			set_string(this);
			return &this->public;
		}
		case AF_INET6:
		{
			if (inet_pton(AF_INET6, string, &this->address6.sin6_addr) <=0)
			{
				break;
			}
			this->address6.sin6_port = htons(port);
			this->socklen = sizeof(struct sockaddr_in6);
			set_string(this);
			return &this->public;
		}
		default:
		{
			break;
		}
	}
	free(this);
	return NULL;
}

/*
 * Described in header.
 */
host_t *host_create_from_chunk(int family, chunk_t address, u_int16_t port)
{
	private_host_t *this = host_create_empty();
	
	this->address.sa_family = family;
	switch (family)
	{
		case AF_INET:
		{
			if (address.len != 4)
			{
				break;
			}
			memcpy(&(this->address4.sin_addr.s_addr), address.ptr,4);
			this->address4.sin_port = htons(port);
			this->socklen = sizeof(struct sockaddr_in);
			set_string(this);
			return &(this->public);
		}
		case AF_INET6:
		{
			if (address.len != 16)
			{
				break;
			}
			memcpy(&(this->address6.sin6_addr.s6_addr), address.ptr, 16);
			this->address6.sin6_port = htons(port);
			this->socklen = sizeof(struct sockaddr_in6);
			set_string(this);
			return &this->public;
		}
		default:
			break;
	}
	free(this);
	return NULL;
}

/*
 * Described in header.
 */
host_t *host_create_from_sockaddr(sockaddr_t *sockaddr)
{
	private_host_t *this = host_create_empty();
	
	switch (sockaddr->sa_family)
	{
		case AF_INET:
		{
			memcpy(&this->address4, sockaddr, sizeof(struct sockaddr_in));
			this->socklen = sizeof(struct sockaddr_in);
			set_string(this);
			return &this->public;
		}
		case AF_INET6:
		{
			memcpy(&this->address6, sockaddr, sizeof(struct sockaddr_in6));
			this->socklen = sizeof(struct sockaddr_in6);
			set_string(this);
			return &this->public;
		}
		default:
			break;
	}
	free(this);
	return NULL;
}
