/*
 * Copyright (C) 2006-2011 Tobias Brunner
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

/**
 * @defgroup kernel_interface kernel_interface
 * @{ @ingroup hkernel
 */

#ifndef KERNEL_INTERFACE_H_
#define KERNEL_INTERFACE_H_

typedef struct kernel_interface_t kernel_interface_t;

#include <utils/host.h>
#include <crypto/prf_plus.h>

#include <kernel/kernel_listener.h>
#include <kernel/kernel_ipsec.h>
#include <kernel/kernel_net.h>

/**
 * Constructor function for ipsec kernel interface
 */
typedef kernel_ipsec_t* (*kernel_ipsec_constructor_t)(void);

/**
 * Constructor function for network kernel interface
 */
typedef kernel_net_t* (*kernel_net_constructor_t)(void);

/**
 * Manager and wrapper for different kernel interfaces.
 *
 * The kernel interface handles the communication with the kernel
 * for SA and policy management and interface and IP address management.
 */
struct kernel_interface_t {

	/**
	 * Get a SPI from the kernel.
	 *
	 * @param src		source address of SA
	 * @param dst		destination address of SA
	 * @param protocol	protocol for SA (ESP/AH)
	 * @param reqid		unique ID for this SA
	 * @param spi		allocated spi
	 * @return				SUCCESS if operation completed
	 */
	status_t (*get_spi)(kernel_interface_t *this, host_t *src, host_t *dst,
						u_int8_t protocol, u_int32_t reqid, u_int32_t *spi);

	/**
	 * Get a Compression Parameter Index (CPI) from the kernel.
	 *
	 * @param src		source address of SA
	 * @param dst		destination address of SA
	 * @param reqid		unique ID for the corresponding SA
	 * @param cpi		allocated cpi
	 * @return				SUCCESS if operation completed
	 */
	status_t (*get_cpi)(kernel_interface_t *this, host_t *src, host_t *dst,
						u_int32_t reqid, u_int16_t *cpi);

	/**
	 * Add an SA to the SAD.
	 *
	 * add_sa() may update an already allocated
	 * SPI (via get_spi). In this case, the replace
	 * flag must be set.
	 * This function does install a single SA for a
	 * single protocol in one direction.
	 *
	 * @param src			source address for this SA
	 * @param dst			destination address for this SA
	 * @param spi			SPI allocated by us or remote peer
	 * @param protocol		protocol for this SA (ESP/AH)
	 * @param reqid			unique ID for this SA
	 * @param mark			optional mark for this SA
	 * @param tfc			Traffic Flow Confidentiality padding for this SA
	 * @param lifetime		lifetime_cfg_t for this SA
	 * @param enc_alg		Algorithm to use for encryption (ESP only)
	 * @param enc_key		key to use for encryption
	 * @param int_alg		Algorithm to use for integrity protection
	 * @param int_key		key to use for integrity protection
	 * @param mode			mode of the SA (tunnel, transport)
	 * @param ipcomp		IPComp transform to use
	 * @param cpi			CPI for IPComp
	 * @param encap			enable UDP encapsulation for NAT traversal
	 * @param esn			TRUE to use Extended Sequence Numbers
	 * @param inbound		TRUE if this is an inbound SA
	 * @param src_ts		traffic selector with BEET source address
	 * @param dst_ts		traffic selector with BEET destination address
	 * @return				SUCCESS if operation completed
	 */
	status_t (*add_sa) (kernel_interface_t *this,
						host_t *src, host_t *dst, u_int32_t spi,
						u_int8_t protocol, u_int32_t reqid, mark_t mark,
						u_int32_t tfc, lifetime_cfg_t *lifetime,
						u_int16_t enc_alg, chunk_t enc_key,
						u_int16_t int_alg, chunk_t int_key,
						ipsec_mode_t mode, u_int16_t ipcomp, u_int16_t cpi,
						bool encap, bool esn, bool inbound,
						traffic_selector_t *src_ts, traffic_selector_t *dst_ts);

	/**
	 * Update the hosts on an installed SA.
	 *
	 * We cannot directly update the destination address as the kernel
	 * requires the spi, the protocol AND the destination address (and family)
	 * to identify SAs. Therefore if the destination address changed we
	 * create a new SA and delete the old one.
	 *
	 * @param spi			SPI of the SA
	 * @param protocol		protocol for this SA (ESP/AH)
	 * @param cpi			CPI for IPComp, 0 if no IPComp is used
	 * @param src			current source address
	 * @param dst			current destination address
	 * @param new_src		new source address
	 * @param new_dst		new destination address
	 * @param encap			current use of UDP encapsulation
	 * @param new_encap		new use of UDP encapsulation
	 * @param mark			optional mark for this SA
	 * @return				SUCCESS if operation completed, NOT_SUPPORTED if
	 *					  the kernel interface can't update the SA
	 */
	status_t (*update_sa)(kernel_interface_t *this,
						  u_int32_t spi, u_int8_t protocol, u_int16_t cpi,
						  host_t *src, host_t *dst,
						  host_t *new_src, host_t *new_dst,
						  bool encap, bool new_encap, mark_t mark);

	/**
	 * Query the number of bytes processed by an SA from the SAD.
	 *
	 * @param src			source address for this SA
	 * @param dst			destination address for this SA
	 * @param spi			SPI allocated by us or remote peer
	 * @param protocol		protocol for this SA (ESP/AH)
	 * @param mark			optional mark for this SA
	 * @param[out] bytes	the number of bytes processed by SA
	 * @return				SUCCESS if operation completed
	 */
	status_t (*query_sa) (kernel_interface_t *this, host_t *src, host_t *dst,
						  u_int32_t spi, u_int8_t protocol, mark_t mark,
						  u_int64_t *bytes);

	/**
	 * Delete a previously installed SA from the SAD.
	 *
	 * @param src			source address for this SA
	 * @param dst			destination address for this SA
	 * @param spi			SPI allocated by us or remote peer
	 * @param protocol		protocol for this SA (ESP/AH)
	 * @param cpi			CPI for IPComp or 0
	 * @param mark			optional mark for this SA
	 * @return				SUCCESS if operation completed
	 */
	status_t (*del_sa) (kernel_interface_t *this, host_t *src, host_t *dst,
						u_int32_t spi, u_int8_t protocol, u_int16_t cpi,
						mark_t mark);

	/**
	 * Flush all SAs from the SAD.
	 *
	 * @return				SUCCESS if operation completed
	 */
	status_t (*flush_sas) (kernel_interface_t *this);

	/**
	 * Add a policy to the SPD.
	 *
	 * A policy is always associated to an SA. Traffic which matches a
	 * policy is handled by the SA with the same reqid.
	 *
	 * @param src			source address of SA
	 * @param dst			dest address of SA
	 * @param src_ts		traffic selector to match traffic source
	 * @param dst_ts		traffic selector to match traffic dest
	 * @param direction		direction of traffic, POLICY_(IN|OUT|FWD)
	 * @param type			type of policy, POLICY_(IPSEC|PASS|DROP)
	 * @param sa			details about the SA(s) tied to this policy
	 * @param mark			mark for this policy
	 * @param priority		priority of this policy
	 * @return				SUCCESS if operation completed
	 */
	status_t (*add_policy) (kernel_interface_t *this,
							host_t *src, host_t *dst,
							traffic_selector_t *src_ts,
							traffic_selector_t *dst_ts,
							policy_dir_t direction, policy_type_t type,
							ipsec_sa_cfg_t *sa, mark_t mark,
							policy_priority_t priority);

	/**
	 * Query the use time of a policy.
	 *
	 * The use time of a policy is the time the policy was used
	 * for the last time.
	 *
	 * @param src_ts		traffic selector to match traffic source
	 * @param dst_ts		traffic selector to match traffic dest
	 * @param direction		direction of traffic, POLICY_(IN|OUT|FWD)
	 * @param mark			optional mark
	 * @param[out] use_time	the time of this SA's last use
	 * @return				SUCCESS if operation completed
	 */
	status_t (*query_policy) (kernel_interface_t *this,
							  traffic_selector_t *src_ts,
							  traffic_selector_t *dst_ts,
							  policy_dir_t direction, mark_t mark,
							  u_int32_t *use_time);

	/**
	 * Remove a policy from the SPD.
	 *
	 * The kernel interface implements reference counting for policies.
	 * If the same policy is installed multiple times (in the case of rekeying),
	 * the reference counter is increased. del_policy() decreases the ref counter
	 * and removes the policy only when no more references are available.
	 *
	 * @param src_ts		traffic selector to match traffic source
	 * @param dst_ts		traffic selector to match traffic dest
	 * @param direction		direction of traffic, POLICY_(IN|OUT|FWD)
	 * @param reqid			unique ID of the associated SA
	 * @param mark			optional mark
	 * @param priority		priority of the policy
	 * @return				SUCCESS if operation completed
	 */
	status_t (*del_policy) (kernel_interface_t *this,
							traffic_selector_t *src_ts,
							traffic_selector_t *dst_ts,
							policy_dir_t direction, u_int32_t reqid,
							mark_t mark, policy_priority_t priority);

	/**
	 * Flush all policies from the SPD.
	 *
	 * @return				SUCCESS if operation completed
	 */
	status_t (*flush_policies) (kernel_interface_t *this);

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
	host_t* (*get_source_addr)(kernel_interface_t *this,
							   host_t *dest, host_t *src);

	/**
	 * Get the next hop for a destination.
	 *
	 * Does a route lookup to get the next hop used to reach dest.
	 * The returned host is allocated and must be destroyed.
	 *
	 * @param dest			target destination address
	 * @return				next hop address, NULL if unreachable
	 */
	host_t* (*get_nexthop)(kernel_interface_t *this, host_t *dest);

	/**
	 * Get the interface name of a local address.
	 *
	 * @param host			address to get interface name from
	 * @return				allocated interface name, or NULL if not found
	 */
	char* (*get_interface) (kernel_interface_t *this, host_t *host);

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
	enumerator_t *(*create_address_enumerator) (kernel_interface_t *this,
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
	status_t (*add_ip) (kernel_interface_t *this, host_t *virtual_ip,
						host_t *iface_ip);

	/**
	 * Remove a virtual IP from an interface.
	 *
	 * The kernel interface uses refcounting, see add_ip().
	 *
	 * @param virtual_ip	virtual ip address to assign
	 * @return				SUCCESS if operation completed
	 */
	status_t (*del_ip) (kernel_interface_t *this, host_t *virtual_ip);

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
	status_t (*add_route) (kernel_interface_t *this, chunk_t dst_net,
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
	status_t (*del_route) (kernel_interface_t *this, chunk_t dst_net,
						   u_int8_t prefixlen, host_t *gateway, host_t *src_ip,
						   char *if_name);

	/**
	 * Set up a bypass policy for a given socket.
	 *
	 * @param fd			socket file descriptor to setup policy for
	 * @param family		protocol family of the socket
	 * @return				TRUE of policy set up successfully
	 */
	bool (*bypass_socket)(kernel_interface_t *this, int fd, int family);

	/**
	 * manager methods
	 */

	/**
	 * Tries to find an ip address of a local interface that is included in the
	 * supplied traffic selector.
	 *
	 * @param ts			traffic selector
	 * @param ip			returned ip (has to be destroyed)
	 * @return				SUCCESS if address found
	 */
	status_t (*get_address_by_ts)(kernel_interface_t *this,
								  traffic_selector_t *ts, host_t **ip);

	/**
	 * Register an ipsec kernel interface constructor on the manager.
	 *
	 * @param create			constructor to register
	 */
	void (*add_ipsec_interface)(kernel_interface_t *this,
								kernel_ipsec_constructor_t create);

	/**
	 * Unregister an ipsec kernel interface constructor.
	 *
	 * @param create			constructor to unregister
	 */
	void (*remove_ipsec_interface)(kernel_interface_t *this,
								   kernel_ipsec_constructor_t create);

	/**
	 * Register a network kernel interface constructor on the manager.
	 *
	 * @param create			constructor to register
	 */
	void (*add_net_interface)(kernel_interface_t *this,
							  kernel_net_constructor_t create);

	/**
	 * Unregister a network kernel interface constructor.
	 *
	 * @param create			constructor to unregister
	 */
	void (*remove_net_interface)(kernel_interface_t *this,
								 kernel_net_constructor_t create);

	/**
	 * Add a listener to the kernel interface.
	 *
	 * @param listener			listener to add
	 */
	void (*add_listener)(kernel_interface_t *this,
						 kernel_listener_t *listener);

	/**
	 * Remove a listener from the kernel interface.
	 *
	 * @param listener			listener to remove
	 */
	void (*remove_listener)(kernel_interface_t *this,
							kernel_listener_t *listener);

	/**
	 * Raise an acquire event.
	 *
	 * @param reqid			reqid of the policy to acquire
	 * @param src_ts		source traffic selector
	 * @param dst_ts		destination traffic selector
	 */
	void (*acquire)(kernel_interface_t *this, u_int32_t reqid,
					traffic_selector_t *src_ts, traffic_selector_t *dst_ts);

	/**
	 * Raise an expire event.
	 *
	 * @param reqid			reqid of the expired SA
	 * @param protocol		protocol of the expired SA
	 * @param spi			spi of the expired SA
	 * @param hard			TRUE if it is a hard expire, FALSE otherwise
	 */
	void (*expire)(kernel_interface_t *this, u_int32_t reqid,
				   u_int8_t protocol, u_int32_t spi, bool hard);

	/**
	 * Raise a mapping event.
	 *
	 * @param reqid			reqid of the SA
	 * @param spi			spi of the SA
	 * @param remote		new remote host
	 */
	void (*mapping)(kernel_interface_t *this, u_int32_t reqid, u_int32_t spi,
					host_t *remote);

	/**
	 * Raise a migrate event.
	 *
	 * @param reqid			reqid of the policy
	 * @param src_ts		source traffic selector
	 * @param dst_ts		destination traffic selector
	 * @param direction		direction of the policy (in|out)
	 * @param local			local host address to be used in the IKE_SA
	 * @param remote		remote host address to be used in the IKE_SA
	 */
	void (*migrate)(kernel_interface_t *this, u_int32_t reqid,
					traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
					policy_dir_t direction, host_t *local, host_t *remote);

	/**
	 * Raise a roam event.
	 *
	 * @param address		TRUE if address list, FALSE if routing changed
	 */
	void (*roam)(kernel_interface_t *this, bool address);

	/**
	 * Destroys a kernel_interface_manager_t object.
	 */
	void (*destroy) (kernel_interface_t *this);
};

/**
 * Creates an object of type kernel_interface_t.
 */
kernel_interface_t *kernel_interface_create(void);

#endif /** KERNEL_INTERFACE_H_ @}*/
