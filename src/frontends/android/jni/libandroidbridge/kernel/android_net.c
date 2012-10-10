/*
 * Copyright (C) 2012 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.  *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "android_net.h"

#include "../charonservice.h"

typedef struct private_kernel_android_net_t private_kernel_android_net_t;

struct private_kernel_android_net_t {

	/**
	 * Public kernel interface
	 */
	kernel_android_net_t public;

	/**
	 * Reference to NetworkManager object
	 */
	network_manager_t *network_manager;
};

METHOD(kernel_net_t, get_source_addr, host_t*,
	private_kernel_android_net_t *this, host_t *dest, host_t *src)
{
	return this->network_manager->get_local_address(this->network_manager,
											dest->get_family(dest) == AF_INET);
}

METHOD(kernel_net_t, add_ip, status_t,
	private_kernel_android_net_t *this, host_t *virtual_ip, host_t *iface_ip)
{
	/* we get the IP from the IKE_SA once the CHILD_SA is established */
	return SUCCESS;
}

METHOD(kernel_net_t, destroy, void,
	private_kernel_android_net_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
kernel_android_net_t *kernel_android_net_create()
{
	private_kernel_android_net_t *this;

	INIT(this,
		.public = {
			.interface = {
				.get_source_addr = _get_source_addr,
				.get_nexthop = (void*)return_null,
				.get_interface = (void*)return_null,
				.create_address_enumerator = (void*)enumerator_create_empty,
				.add_ip = _add_ip,
				.del_ip = (void*)return_failed,
				.add_route = (void*)return_failed,
				.del_route = (void*)return_failed,
				.destroy = _destroy,
			},
		},
		.network_manager = charonservice->get_network_manager(charonservice),
	);

	return &this->public;
};
