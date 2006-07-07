/**
 * @file kernel_interface.h
 *
 * @brief Interface of kernel_interface_t.
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

#ifndef KERNEL_INTERFACE_H_
#define KERNEL_INTERFACE_H_

#include <linux/xfrm.h>

#include <utils/host.h>
#include <crypto/prf_plus.h>
#include <encoding/payloads/proposal_substructure.h>

typedef struct natt_conf_t natt_conf_t;

/**
 * @brief Configuration for NAT-T
 */
struct natt_conf_t {
	u_int16_t sport, dport;
};

typedef struct kernel_interface_t kernel_interface_t;

/**
 * @brief Interface to the kernel.
 * 
 * The kernel interface handles the communication with the kernel
 * for SA and policy management. It allows setup of these, and provides 
 * further the handling of kernel events.
 * 
 * @b Constructors:
 *  - kernel_interface_create()
 * 
 * @ingroup threads
 */
struct kernel_interface_t {

	/**
	 * @brief Get a SPI from the kernel.
	 *
	 * @warning get_spi() implicitely creates an SA with
	 * the allocated SPI, therefore the replace flag
	 * in add_sa() must be set when installing this SA.
	 * 
	 * @param this		calling object
	 * @param src		source address of SA
	 * @param dst		destination address of SA
	 * @param protocol	protocol for SA (ESP/AH)
	 * @param reqid		unique ID for this SA
	 * @param[out] spi	allocated spi
	 * @return
	 * 					- SUCCESS
	 * 					- FAILED if kernel comm failed
	 */
	status_t (*get_spi) (kernel_interface_t *this, 
				host_t *src, host_t *dst, 
				protocol_id_t protocol, 
				u_int32_t reqid,
				u_int32_t *spi);
	
	/**
	 * @brief Add an SA to the SAD.
	 * 
	 * add_sa() may update an already allocated
	 * SPI (via get_spi). In this case, the replace
	 * flag must be set.
	 * This function does install a single SA for a
	 * single protocol in one direction. The kernel-interface
	 * gets the keys itself from the PRF, as we don't know
	 * his algorithms and key sizes.
	 * 
	 * @param this			calling object
	 * @param src			source address for this SA
	 * @param dst			destination address for this SA
	 * @param spi			SPI allocated by us or remote peer
	 * @param protocol		protocol for this SA (ESP/AH)
	 * @param reqid			unique ID for this SA
	 * @param expire_soft	lifetime in seconds before rekeying
	 * @param expire_hard	lieftime in seconds before delete
	 * @param enc_alg		Algorithm to use for encryption (ESP only)
	 * @param int_alg		Algorithm to use for integrity protection
	 * @param prf_plus		PRF to derive keys
	 * @param natt			NAT-T Configuration
	 * @param replace		Should an already installed SA be updated?
	 * @return
	 * 						- SUCCESS
	 * 						- FAILED if kernel comm failed
	 */
	status_t (*add_sa)(kernel_interface_t *this,
				host_t *src, host_t *dst,
				u_int32_t spi,
				protocol_id_t protocol,
				u_int32_t reqid,
				u_int64_t expire_soft,
				u_int64_t expire_hard,
				algorithm_t *enc_alg,
				algorithm_t *int_alg,
				prf_plus_t *prf_plus,
				natt_conf_t *natt,
				bool replace);
	
	/**
	 * @brief Update the hosts on an installed SA. Encapsulation ports are also updated.
	 *
	 * @note We cannot directly update the destination address as the kernel requires the spi,
	 * the protocol AND the destination address (and family) to identify SAs. Therefore if the 
	 * destination address changed we create a new SA and delete the old one.
	 *
	 * @param this		calling object
	 * @param src		source address for this SA
	 * @param dst		destination address for this SA
	 * @param new_src	new source address for this SA
	 * @param new_dst	new destination address for this SA
	 * @param src_changes	changes in src
	 * @param dst_changes	changes in dst
	 * @param spi		SPI allocated by us or remote peer
	 * @param protocol	protocol for this SA (ESP/AH)
	 * @return
	 * 					- SUCCESS
	 * 					- FAILED if kernel comm failed
	 */
	status_t (*update_sa_hosts)(kernel_interface_t *this,
				host_t *src, host_t *dst,
				host_t *new_src, host_t *new_dst,
				int src_changes, int dst_changes,
				u_int32_t spi, protocol_id_t protocol);
	
	/**
	 * @brief Delete a previusly installed SA from the SAD.
	 * 
	 * @param this		calling object
	 * @param dst		destination address for this SA
	 * @param spi		SPI allocated by us or remote peer
	 * @param protocol	protocol for this SA (ESP/AH)
	 * @return
	 * 					- SUCCESS
	 * 					- FAILED if kernel comm failed
	 */
	status_t (*del_sa) (kernel_interface_t *this,
				host_t *dst,
				u_int32_t spi,
				protocol_id_t protocol);
	
	/**
	 * @brief Add a policy to the SPD.
	 * 
	 * A policy is always associated to an SA, so
	 * traffic applied to a policy. Traffic which
	 * matches a policy is handled by the SA with the same
	 * reqid.
	 * 
	 * @param this			calling object
	 * @param me			address of local peer
	 * @param other			address of remote peer
	 * @param src			src address of traffic this policy applies
	 * @param dst			dest address of traffic this policy applies
	 * @param src_hostbits	subnetmask to use for src address
	 * @param dst_hostbits	subnetmask to use for dst address
	 * @param direction		direction of traffic, XFRM_POLICY_OUT, XFRM_POLICY_IN, XFRM_POLICY_FWD
	 * @param upper_proto	upper layer protocol of traffic for this policy (TCP, UDP, ICMP, ...)
	 * @param protocol		protocol to use to protect traffic (AH/ESP)
	 * @param reqid			uniqe ID of an SA to use to enforce policy
	 * @return
	 * 						- SUCCESS
	 * 						- FAILED if kernel comm failed
	 */
	status_t (*add_policy) (kernel_interface_t *this, 
				host_t *me, host_t *other, 
				host_t *src, host_t *dst,
				u_int8_t src_hostbits, u_int8_t dst_hostbits,
				int direction, int upper_proto, 
				protocol_id_t protocol,
				u_int32_t reqid);
	/**
	 * @brief Query the use time of a policy
	 * 
	 * @param this			calling object
	 * @param me			address of local peer
	 * @param other			address of remote peer
	 * @param src			src address of traffic this policy applies
	 * @param dst			dest address of traffic this policy applies
	 * @param src_hostbits	subnetmask to use for src address
	 * @param dst_hostbits	subnetmask to use for dst address
	 * @param direction		direction of traffic, XFRM_POLICY_OUT, XFRM_POLICY_IN, XFRM_POLICY_FWD
	 * @param upper_proto	upper layer protocol of traffic for this policy (TCP, UDP, ICMP, ...)
	 * @param use_time		the time of this policy's last use
	 * @return
	 * 						- SUCCESS
	 * 						- FAILED if kernel comm failed
	 */
	status_t (*query_policy) (kernel_interface_t *this, 
				host_t *me, host_t *other,
				host_t *src, host_t *dst,
				u_int8_t src_hostbits, u_int8_t dst_hostbits,
				int direction, int upper_proto,
				time_t *use_time);
	
	/**
	 * @brief Remove a policy from the SPD.
	 * 
	 * @param this			calling object
	 * @param me			address of local peer
	 * @param other			address of remote peer
	 * @param src			src address of traffic this policy applies
	 * @param dst			dest address of traffic this policy applies
	 * @param src_hostbits	subnetmask to use for src address
	 * @param dst_hostbits	subnetmask to use for dst address
	 * @param direction		direction of traffic, XFRM_POLICY_OUT, XFRM_POLICY_IN, XFRM_POLICY_FWD
	 * @param upper_proto	upper layer protocol of traffic for this policy (TCP, UDP, ICMP, ...)
	 * @return
	 * 						- SUCCESS
	 * 						- FAILED if kernel comm failed
	 */
	status_t (*del_policy) (kernel_interface_t *this, 
				host_t *me, host_t *other,
				host_t *src, host_t *dst,
				u_int8_t src_hostbits, u_int8_t dst_hostbits,
				int direction, int upper_proto);
	
	/**
	 * @brief Destroys a kernel_interface object.
	 *
	 * @param kernel_interface_t 	calling object
	 */
	void (*destroy) (kernel_interface_t *kernel_interface);
};

/**
 * @brief Creates an object of type kernel_interface_t.
 * 
 * @ingroup threads
 */
kernel_interface_t *kernel_interface_create(void);

#endif /*KERNEL_INTERFACE_H_*/
