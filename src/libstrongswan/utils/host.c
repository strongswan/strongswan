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
 */

#define _GNU_SOURCE
#include <sys/socket.h>
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
	 * low-lewel structure, which stores the address
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


METHOD(host_t, get_sockaddr, sockaddr_t*,
	private_host_t *this)
{
	return &(this->address);
}

METHOD(host_t, get_sockaddr_len, socklen_t*,
	private_host_t *this)
{
	return &(this->socklen);
}

METHOD(host_t, is_anyaddr, bool,
	private_host_t *this)
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
		snprintf(buffer, sizeof(buffer), "%%any%s",
				 this->address.sa_family == AF_INET6 ? "6" : "");
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

METHOD(host_t, get_address, chunk_t,
	private_host_t *this)
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

METHOD(host_t, get_family, int,
	private_host_t *this)
{
	return this->address.sa_family;
}

METHOD(host_t, get_port, u_int16_t,
	private_host_t *this)
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

METHOD(host_t, set_port, void,
	private_host_t *this, u_int16_t port)
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

METHOD(host_t, clone_, host_t*,
	private_host_t *this)
{
	private_host_t *new;

	new = malloc_thing(private_host_t);
	memcpy(new, this, sizeof(private_host_t));

	return &new->public;
}

/**
 * Implements host_t.ip_equals
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

METHOD(host_t, destroy, void,
	private_host_t *this)
{
	free(this);
}

/**
 * Creates an empty host_t object
 */
static private_host_t *host_create_empty(void)
{
	private_host_t *this;

	INIT(this,
		.public = {
			.get_sockaddr = _get_sockaddr,
			.get_sockaddr_len = _get_sockaddr_len,
			.clone = _clone_,
			.get_family = _get_family,
			.get_address = _get_address,
			.get_port = _get_port,
			.set_port = _set_port,
			.get_differences = get_differences,
			.ip_equals = (bool (*)(host_t *,host_t *))ip_equals,
			.equals = (bool (*)(host_t *,host_t *)) equals,
			.is_anyaddr = _is_anyaddr,
			.destroy = _destroy,
		},
	);

	return this;
}

/*
 * Create a %any host with port
 */
static host_t *host_create_any_port(int family, u_int16_t port)
{
	host_t *this;

	this = host_create_any(family);
	this->set_port(this, port);
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
		return host_create_any_port(AF_INET, port);
	}
	if (streq(string, "%any6"))
	{
		return host_create_any_port(AF_INET6, port);
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
host_t *host_create_from_dns(char *string, int af, u_int16_t port)
{
	private_host_t *this;
	struct addrinfo hints, *result;
	int error;

	if (streq(string, "%any"))
	{
		return host_create_any_port(af ? af : AF_INET, port);
	}
	if (streq(string, "%any6"))
	{
		return host_create_any_port(af ? af : AF_INET6, port);
	}
	if (af == AF_INET && strchr(string, ':'))
	{	/* do not try to convert v6 addresses for v4 family */
		return NULL;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	error = getaddrinfo(string, NULL, &hints, &result);
	if (error != 0)
	{
		DBG1(DBG_LIB, "resolving '%s' failed: %s", string, gai_strerror(error));
		return NULL;
	}
	/* result is a linked list, but we use only the first address */
	this = (private_host_t*)host_create_from_sockaddr(result->ai_addr);
	freeaddrinfo(result);
	if (this)
	{
		switch (this->address.sa_family)
		{
			case AF_INET:
				this->address4.sin_port = htons(port);
				break;
			case AF_INET6:
				this->address6.sin6_port = htons(port);
				break;
		}
		return &this->public;
	}
	return NULL;
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
host_t *host_create_from_subnet(char *string, int *bits)
{
	char *pos, buf[64];
	host_t *net;

	pos = strchr(string, '/');
	if (pos)
	{
		if (pos - string >= sizeof(buf))
		{
			return NULL;
		}
		strncpy(buf, string, pos - string);
		buf[pos - string] = '\0';
		*bits = atoi(pos + 1);
		return host_create_from_string(buf, 0);
	}
	net = host_create_from_string(string, 0);
	if (net)
	{
		if (net->get_family(net) == AF_INET)
		{
			*bits = 32;
		}
		else
		{
			*bits = 128;
		}
	}
	return net;
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
	free(this);
	return NULL;
}
