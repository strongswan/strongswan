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

#include "kernel_iph_net.h"

#include <hydra.h>

typedef struct private_kernel_iph_net_t private_kernel_iph_net_t;

/**
 * Private data of kernel_iph_net implementation.
 */
struct private_kernel_iph_net_t {

	/**
	 * Public interface.
	 */
	kernel_iph_net_t public;
};

METHOD(kernel_net_t, get_interface_name, bool,
	private_kernel_iph_net_t *this, host_t* ip, char **name)
{
	return FALSE;
}

METHOD(kernel_net_t, create_address_enumerator, enumerator_t*,
	private_kernel_iph_net_t *this, kernel_address_type_t which)
{
	return enumerator_create_empty();
}

METHOD(kernel_net_t, get_source_addr, host_t*,
	private_kernel_iph_net_t *this, host_t *dest, host_t *src)
{
	return NULL;
}

METHOD(kernel_net_t, get_nexthop, host_t*,
	private_kernel_iph_net_t *this, host_t *dest, host_t *src)
{
	return NULL;
}

METHOD(kernel_net_t, add_ip, status_t,
	private_kernel_iph_net_t *this, host_t *virtual_ip, int prefix,
	char *iface_name)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_net_t, del_ip, status_t,
	private_kernel_iph_net_t *this, host_t *virtual_ip, int prefix,
	bool wait)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_net_t, add_route, status_t,
	private_kernel_iph_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_net_t, del_route, status_t,
	private_kernel_iph_net_t *this, chunk_t dst_net, u_int8_t prefixlen,
	host_t *gateway, host_t *src_ip, char *if_name)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_net_t, destroy, void,
	private_kernel_iph_net_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
kernel_iph_net_t *kernel_iph_net_create()
{
	private_kernel_iph_net_t *this;

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
