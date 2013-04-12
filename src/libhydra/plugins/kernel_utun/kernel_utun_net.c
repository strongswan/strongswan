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

#include "kernel_utun_net.h"

#include <hydra.h>
#include <utils/debug.h>
#include <networking/tun_device.h>

typedef struct private_kernel_utun_net_t private_kernel_utun_net_t;

/**
 * Private variables and functions of kernel_utun_net class.
 */
struct private_kernel_utun_net_t {

	/**
	 * Public part of the kernel_utun_net_t object.
	 */
	kernel_utun_net_t public;

	/**
	 * Active utun interface
	 */
	tun_device_t *tun;
};

METHOD(kernel_net_t, create_address_enumerator, enumerator_t*,
	private_kernel_utun_net_t *this, kernel_address_type_t which)
{
	return enumerator_create_empty();
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
	if (this->tun)
	{	/* only one for now */
		return FAILED;
	}
	if (prefix == -1)
	{
		switch (virtual_ip->get_family(virtual_ip))
		{
			case AF_INET:
				prefix = 32;
				break;
			case AF_INET6:
				prefix = 128;
				break;
			default:
				return NOT_SUPPORTED;
		}
	}
	this->tun = tun_device_create(NULL);
	if (!this->tun)
	{
		return FAILED;
	}
	if (!this->tun->set_address(this->tun, virtual_ip, prefix))
	{
		this->tun->destroy(this->tun);
		this->tun = NULL;
		return FAILED;
	}
	return SUCCESS;
}

METHOD(kernel_net_t, del_ip, status_t,
	private_kernel_utun_net_t *this, host_t *virtual_ip, int prefix,
	bool wait)
{
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
	if (this->tun)
	{
		this->tun->destroy(this->tun);
	}
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
