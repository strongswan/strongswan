/*
 * Copyright (C) 2006-2009 Tobias Brunner
 * Copyright (C) 2006 Daniel Roethlisberger
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
 *
 * $Id$
 */

#define _GNU_SOURCE
#include <netdb.h>
#include <string.h>

#include "host.h"

#include <debug.h>

#define IPV4_LEN	 4
#define IPV6_LEN	16

typedef struct private_host_t private_host_t;

/**
 * Private Data of a host object.
 */
struct private_host_t { 	
	/**
	 * Public data
	 */
	host_t public;
	
	/**
	 * low-lewel structure, wich stores the address
	 */
	union {
		/** generic type */
		struct sockaddr address;
		/** maximum sockaddr size */
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
			u_int8_t zeroes[IPV4_LEN];

			memset(zeroes, 0, IPV4_LEN);
			return memeq(zeroes, &(this->address4.sin_addr.s_addr), IPV4_LEN);
		}
		case AF_INET6:
		{
			u_int8_t zeroes[IPV6_LEN];

			memset(zeroes, 0, IPV6_LEN);
			return memeq(zeroes, &(this->address6.sin6_addr.s6_addr), IPV6_LEN);
		}
		default:
		{
			return FALSE;
		}	
	}
}

/**
 * Described in header.
 */
int host_printf_hook(char *dst, size_t dstlen, printf_hook_spec_t *spec,
					 const void *const *args)
{
	private_host_t *this = *((private_host_t**)(args[0]));
	char buffer[INET6_ADDRSTRLEN + 16];
	
	if (this == NULL)
	{
		snprintf(buffer, sizeof(buffer), "(null)");
	}
	else if (is_anyaddr(this))
	{
		snprintf(buffer, sizeof(buffer), "%%any");
	}
	else
	{
		void *address;
		u_int16_t port;
		int len;
		
		address = &this->address6.sin6_addr;
		port = this->address6.sin6_port;
		
		switch (this->address.sa_family)
		{
			case AF_INET:
				address = &this->address4.sin_addr;
				port = this->address4.sin_port;
				/* fall */
			case AF_INET6:
	
				if (inet_ntop(this->address.sa_family, address,
							  buffer, sizeof(buffer)) == NULL)
				{
					snprintf(buffer, sizeof(buffer),
							 "(address conversion failed)");
				}
				else if (spec->hash)
				{
					len = strlen(buffer);
					snprintf(buffer + len, sizeof(buffer) - len,
							 "[%d]", ntohs(port));
				}
				break;
			default:
				snprintf(buffer, sizeof(buffer), "(family not supported)");
				break;
		}
	}
	if (spec->minus)
	{
		return print_in_hook(dst, dstlen, "%-*s", spec->width, buffer);
	}
	return print_in_hook(dst, dstlen, "%*s", spec->width, buffer);
}

/**
 * Implementation of host_t.get_address.
 */
static chunk_t get_address(private_host_t *this)
{
	chunk_t address = chunk_empty;
	
	switch (this->address.sa_family) 
	{
		case AF_INET:
		{
			address.ptr = (char*)&(this->address4.sin_addr.s_addr);
			address.len = IPV4_LEN;
			return address;
		}
		case AF_INET6:
		{
			address.ptr = (char*)&(this->address6.sin6_addr.s6_addr);
			address.len = IPV6_LEN;
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
static private_host_t *clone_(private_host_t *this)
{
	private_host_t *new = malloc_thing(private_host_t);
	
	memcpy(new, this, sizeof(private_host_t));
	return new;
}

/**
 * Impelements host_t.ip_equals
 */
static bool ip_equals(private_host_t *this, private_host_t *other)
{
	if (this->address.sa_family != other->address.sa_family)
	{
		/* 0.0.0.0 and 0::0 are equal */
		return (is_anyaddr(this) && is_anyaddr(other));
	}
	
	switch (this->address.sa_family)
	{
		case AF_INET:
		{
			return memeq(&this->address4.sin_addr, &other->address4.sin_addr,
						 sizeof(this->address4.sin_addr));
		}
		case AF_INET6:
		{
			return memeq(&this->address6.sin6_addr, &other->address6.sin6_addr,
						 sizeof(this->address6.sin6_addr));
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
 * Implements host_t.equals
 */
static bool equals(private_host_t *this, private_host_t *other)
{
	if (!ip_equals(this, other))
	{
		return FALSE;
	}
	
	switch (this->address.sa_family)
	{
		case AF_INET:
		{
			return (this->address4.sin_port == other->address4.sin_port);
		}
		case AF_INET6:
		{
			return (this->address6.sin6_port == other->address6.sin6_port);
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
	this->public.clone = (host_t* (*) (host_t*))clone_;
	this->public.get_family = (int (*) (host_t*))get_family;
	this->public.get_address = (chunk_t (*) (host_t *)) get_address;
	this->public.get_port = (u_int16_t (*) (host_t *))get_port;
	this->public.set_port = (void (*) (host_t *,u_int16_t))set_port;
	this->public.get_differences = get_differences;
	this->public.ip_equals = (bool (*) (host_t *,host_t *)) ip_equals;
	this->public.equals = (bool (*) (host_t *,host_t *)) equals;
	this->public.is_anyaddr = (bool (*) (host_t *)) is_anyaddr;
	this->public.destroy = (void (*) (host_t*))destroy;
	
	return this;
}

/*
 * Described in header.
 */
host_t *host_create_from_string(char *string, u_int16_t port)
{
	private_host_t *this;
	
	if (streq(string, "%any"))
	{
		return host_create_any(AF_INET);
	}
	if (streq(string, "%any6"))
	{
		return host_create_any(AF_INET6);
	}
	
	this = host_create_empty();
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
host_t *host_create_from_dns(char *string, int af, u_int16_t port)
{
	private_host_t *this;
	struct hostent host, *ptr;
	char buf[512];
	int err, ret;

	if (streq(string, "%any"))
	{
		return host_create_any(af ? af : AF_INET);
	}
	if (streq(string, "%any6"))
	{
		return host_create_any(af ? af : AF_INET6);
	}
	else if (strchr(string, ':'))
	{
		/* gethostbyname does not like IPv6 addresses - fallback */
		return host_create_from_string(string, port);
	}
	
	if (af)
	{	
		ret = gethostbyname2_r(string, af, &host, buf, sizeof(buf), &ptr, &err);
	}
	else
	{
		ret = gethostbyname_r(string, &host, buf, sizeof(buf), &ptr, &err);
	}
	if (ret != 0)
	{
		DBG1("resolving '%s' failed: %s", string, hstrerror(err));
		return NULL;
	}
	if (ptr == NULL)
	{
		DBG1("resolving '%s' failed", string);
	}
	this = host_create_empty();
	this->address.sa_family = host.h_addrtype;
	switch (this->address.sa_family)
	{
		case AF_INET:
			memcpy(&this->address4.sin_addr.s_addr,
				   host.h_addr_list[0], host.h_length);
			this->address4.sin_port = htons(port);
			this->socklen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			memcpy(&this->address6.sin6_addr.s6_addr,
				   host.h_addr_list[0], host.h_length);
			this->address6.sin6_port = htons(port);
			this->socklen = sizeof(struct sockaddr_in6);
			break;
		default:
			free(this);
			return NULL;
	}
	return &this->public;
}

/*
 * Described in header.
 */
host_t *host_create_from_chunk(int family, chunk_t address, u_int16_t port)
{
	private_host_t *this;
	
	switch (family)
	{
		case AF_INET:
			if (address.len < IPV4_LEN)
			{
				return NULL;
			}
			address.len = IPV4_LEN;
			break;
		case AF_INET6:
			if (address.len < IPV6_LEN)
			{
				return NULL;
			}
			address.len = IPV6_LEN;
			break;
		case AF_UNSPEC:
			switch (address.len)
			{
				case IPV4_LEN:
					family = AF_INET;
					break;
				case IPV6_LEN:
					family = AF_INET6;
					break;
				default:
					return NULL;
			}
			break;
		default:
			return NULL;
	}
	this = host_create_empty();
	this->address.sa_family = family;
	switch (family)
	{
		case AF_INET:
			memcpy(&this->address4.sin_addr.s_addr, address.ptr, address.len);
			this->address4.sin_port = htons(port);
			this->socklen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			memcpy(&this->address6.sin6_addr.s6_addr, address.ptr, address.len);
			this->address6.sin6_port = htons(port);
			this->socklen = sizeof(struct sockaddr_in6);
			break;
	}
	return &this->public;
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
			return &this->public;
		}
		case AF_INET6:
		{
			memcpy(&this->address6, sockaddr, sizeof(struct sockaddr_in6));
			this->socklen = sizeof(struct sockaddr_in6);
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
host_t *host_create_any(int family)
{
	private_host_t *this = host_create_empty();
	
	memset(&this->address_max, 0, sizeof(struct sockaddr_storage));
	this->address.sa_family = family;
	
	switch (family)
	{
		case AF_INET:
		{
			this->socklen = sizeof(struct sockaddr_in);
			return &(this->public);
		}
		case AF_INET6:
		{
			this->socklen = sizeof(struct sockaddr_in6);
			return &this->public;
		}
		default:
			break;
	}
	return NULL;
}
