/**
 * @file kernel_interface.h
 *
 * @brief Interface of kernel_interface_t.
 *
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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
#include <encoding/payloads/proposal_substructure.h>

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
	 * single protocol in one direction.
	 * 
	 * @param this		calling object
	 * @param src		source address for this SA
	 * @param dst		destination address for this SA
	 * @param spi		SPI allocated by us or remote peer
	 * @param protocol	protocol for this SA (ESP/AH)
	 * @param reqid		unique ID for this SA
	 * @param enc_alg	Algorithm to use for encryption (ESP only)
	 * @param enc_key	Key to use for encryption
	 * @param int_alg	Algorithm to use for integrity protection
	 * @param int_key	Key for integrity protection
	 * @param replace	Should an already installed SA be updated?
	 * @return
	 * 					- SUCCESS
	 * 					- FAILED if kernel comm failed
	 */
	status_t (*add_sa)(kernel_interface_t *this,
				host_t *src, host_t *dst,
				u_int32_t spi,
				protocol_id_t protocol,
				u_int32_t reqid,
				encryption_algorithm_t enc_alg,
				chunk_t enc_key,
				integrity_algorithm_t int_alg,
				chunk_t int_key,
				bool replace);
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
	 * @param ah			protect traffic with AH?
	 * @param esp			protect traffic with ESP?
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
				bool ah, bool esp,
				u_int32_t reqid);
	
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
