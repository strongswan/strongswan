/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <errno.h>

#include "kernel_utun_net.h"
#include "kernel_utun_ipsec.h"

#include <hydra.h>
#include <utils/debug.h>

typedef struct private_kernel_utun_net_t private_kernel_utun_net_t;

/**
 * Private variables and functions of kernel_utun_net class.
 */
struct private_kernel_utun_net_t {

	/**
	 * Public part of the kernel_utun_net_t object.
	 */
	kernel_utun_net_t public;
};

typedef struct {
	/** implements enumerator */
	enumerator_t public;
	/** ifaddrs to free on cleanup */
	struct ifaddrs *orig;
	/** currently enumerating ifaddr */
	struct ifaddrs *current;
	/** current host */
	host_t *host;
} addr_enumerator_t;

METHOD(enumerator_t, addr_enumerate, bool,
	addr_enumerator_t *this, host_t **addr)
{
	while (TRUE)
	{
		DESTROY_IF(this->host);
		this->host = NULL;
		if (this->current)
		{
			this->current = this->current->ifa_next;
		}
		else
		{
			this->current = this->orig;
		}
		if (!this->current)
		{
			return FALSE;
		}
		if (!this->current->ifa_addr)
		{
			return FALSE;
		}
		/* TODO: filter based on "which" */
		this->host = host_create_from_sockaddr(this->current->ifa_addr);
		if (!this->host)
		{
			continue;
		}
		*addr = this->host;
		return TRUE;
	}
}

METHOD(enumerator_t, addr_destroy, void,
	addr_enumerator_t *this)
{
	if (this->orig)
	{
		freeifaddrs(this->orig);
	}
	DESTROY_IF(this->host);
	free(this);
}

METHOD(kernel_net_t, create_address_enumerator, enumerator_t*,
	private_kernel_utun_net_t *this, kernel_address_type_t which)
{
	addr_enumerator_t *enumerator;
	struct ifaddrs *ifa;

	if (getifaddrs(&ifa) != 0)
	{
		return enumerator_create_empty();
	}
	INIT(enumerator,
		.public = {
			.enumerate = (void*)_addr_enumerate,
			.destroy = _addr_destroy,
		},
		.orig = ifa,
	);
	return &enumerator->public;
}

METHOD(kernel_net_t, get_interface_name, bool,
	private_kernel_utun_net_t *this, host_t* ip, char **name)
{
	struct ifaddrs *ifa, *current;
	host_t *host;
	bool found = FALSE;

	if (getifaddrs(&ifa) != 0)
	{
		return FALSE;
	}
	for (current = ifa; current; current = current->ifa_next)
	{
		if (current->ifa_addr)
		{
			host = host_create_from_sockaddr(current->ifa_addr);
			if (host)
			{
				if (ip->ip_equals(ip, host))
				{
					*name = strdup(current->ifa_name);
					found = TRUE;
				}
				host->destroy(host);
			}
		}
		if (found)
		{
			break;
		}
	}
	freeifaddrs(ifa);

	return found;
}

METHOD(kernel_net_t, get_source_addr, host_t*,
	private_kernel_utun_net_t *this, host_t *dest, host_t *src)
{
	return NULL;
}

METHOD(kernel_net_t, get_nexthop, host_t*,
	private_kernel_utun_net_t *this, host_t *dest, host_t *src)
{
	return NULL;
}

METHOD(kernel_net_t, add_ip, status_t,
	private_kernel_utun_net_t *this, host_t *virtual_ip, int prefix,
	char *iface_name)
{
	kernel_utun_ipsec_t *ipsec;

	ipsec = kernel_utun_ipsec_get();
	if (ipsec)
	{
		return ipsec->add_ip(ipsec, virtual_ip, prefix);
	}
	return FAILED;
}

METHOD(kernel_net_t, del_ip, status_t,
	private_kernel_utun_net_t *this, host_t *virtual_ip, int prefix,
	bool wait)
{
	kernel_utun_ipsec_t *ipsec;

	ipsec = kernel_utun_ipsec_get();
	if (ipsec)
	{
		return ipsec->del_ip(ipsec, virtual_ip, prefix);
	}
	return FAILED;
}

METHOD(kernel_net_t, add_route, status_t,
	private_kernel_utun_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name)
{
	return FAILED;
}

METHOD(kernel_net_t, del_route, status_t,
	private_kernel_utun_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name)
{
	return FAILED;
}

METHOD(kernel_net_t, destroy, void,
	private_kernel_utun_net_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
kernel_utun_net_t *kernel_utun_net_create()
{
	private_kernel_utun_net_t *this;

	INIT(this,
		.public = {
			.interface = {
				.get_interface = _get_interface_name,
				.create_address_enumerator = _create_address_enumerator,
				.get_source_addr = _get_source_addr,
				.get_nexthop = _get_nexthop,
				.add_ip = _add_ip,
				.del_ip = _del_ip,
				.add_route = _add_route,
				.del_route = _del_route,
				.destroy = _destroy,
			},
		},
	);

	return &this->public;
}
