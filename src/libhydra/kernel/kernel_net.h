/*
 * Copyright (C) 2008 Tobias Brunner
 * Copyright (C) 2007 Martin Willi
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

/**
 * @defgroup kernel_net kernel_net
 * @{ @ingroup hkernel
 */

#ifndef KERNEL_NET_H_
#define KERNEL_NET_H_

typedef struct kernel_net_t kernel_net_t;

#include <utils/enumerator.h>
#include <utils/host.h>
#include <plugins/plugin.h>

/**
 * Interface to the network subsystem of the kernel.
 *
 * The kernel network interface handles the communication with the kernel
 * for interface and IP address management.
 */
struct kernel_net_t {

	/**
	 * Get our outgoing source address for a destination.
	 *
	 * Does a route lookup to get the source address used to reach dest.
	 * The returned host is allocated and must be destroyed.
	 * An optional src address can be used to check if a route is available
	 * for given source to dest.
	 *
	 * @param dest			target destination address
	 * @param src			source address to check, or NULL
	 * @return				outgoing source address, NULL if unreachable
	 */
	host_t* (*get_source_addr)(kernel_net_t *this, host_t *dest, host_t *src);

	/**
	 * Get the next hop for a destination.
	 *
	 * Does a route lookup to get the next hop used to reach dest.
	 * The returned host is allocated and must be destroyed.
	 *
	 * @param dest			target destination address
	 * @return				next hop address, NULL if unreachable
	 */
	host_t* (*get_nexthop)(kernel_net_t *this, host_t *dest);

	/**
	 * Get the interface name of a local address.
	 *
	 * @param host			address to get interface name from
	 * @return				allocated interface name, or NULL if not found
	 */
	char* (*get_interface) (kernel_net_t *this, host_t *host);

	/**
	 * Creates an enumerator over all local addresses.
	 *
	 * This function blocks an internal cached address list until the
	 * enumerator gets destroyed.
	 * The hosts are read-only, do not modify of free.
	 *
	 * @param include_down_ifaces	TRUE to enumerate addresses from down interfaces
	 * @param include_virtual_ips	TRUE to enumerate virtual ip addresses
	 * @return						enumerator over host_t's
	 */
	enumerator_t *(*create_address_enumerator) (kernel_net_t *this,
						bool include_down_ifaces, bool include_virtual_ips);

	/**
	 * Add a virtual IP to an interface.
	 *
	 * Virtual IPs are attached to an interface. If an IP is added multiple
	 * times, the IP is refcounted and not removed until del_ip() was called
	 * as many times as add_ip().
	 * The virtual IP is attached to the interface where the iface_ip is found.
	 *
	 * @param virtual_ip	virtual ip address to assign
	 * @param iface_ip		IP of an interface to attach virtual IP
	 * @return				SUCCESS if operation completed
	 */
	status_t (*add_ip) (kernel_net_t *this, host_t *virtual_ip,
						host_t *iface_ip);

	/**
	 * Remove a virtual IP from an interface.
	 *
	 * The kernel interface uses refcounting, see add_ip().
	 *
	 * @param virtual_ip	virtual ip address to assign
	 * @return				SUCCESS if operation completed
	 */
	status_t (*del_ip) (kernel_net_t *this, host_t *virtual_ip);

	/**
	 * Add a route.
	 *
	 * @param dst_net		destination net
	 * @param prefixlen		destination net prefix length
	 * @param gateway		gateway for this route
	 * @param src_ip		sourc ip of the route
	 * @param if_name		name of the interface the route is bound to
	 * @return				SUCCESS if operation completed
	 *						ALREADY_DONE if the route already exists
	 */
	status_t (*add_route) (kernel_net_t *this, chunk_t dst_net,
						   u_int8_t prefixlen, host_t *gateway, host_t *src_ip,
						   char *if_name);

	/**
	 * Delete a route.
	 *
	 * @param dst_net		destination net
	 * @param prefixlen		destination net prefix length
	 * @param gateway		gateway for this route
	 * @param src_ip		sourc ip of the route
	 * @param if_name		name of the interface the route is bound to
	 * @return				SUCCESS if operation completed
	 */
	status_t (*del_route) (kernel_net_t *this, chunk_t dst_net,
						   u_int8_t prefixlen, host_t *gateway, host_t *src_ip,
						   char *if_name);

	/**
	 * Destroy the implementation.
	 */
	void (*destroy) (kernel_net_t *this);
};

/**
 * Helper function to (un-)register net kernel interfaces from plugin features.
 *
 * This function is a plugin_feature_callback_t and can be used with the
 * PLUGIN_CALLBACK macro to register an net kernel interface constructor.
 *
 * @param plugin		plugin registering the kernel interface
 * @param feature		associated plugin feature
 * @param reg			TRUE to register, FALSE to unregister
 * @param data			data passed to callback, an kernel_net_constructor_t
 */
bool kernel_net_register(plugin_t *plugin, plugin_feature_t *feature,
						 bool reg, void *data);

#endif /** KERNEL_NET_H_ @}*/
