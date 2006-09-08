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

#include <utils/host.h>
#include <crypto/prf_plus.h>
#include <encoding/payloads/proposal_substructure.h>

typedef struct natt_conf_t natt_conf_t;

/**
 * Configuration for NAT-T
 */
struct natt_conf_t {
	/** source port to use for UDP-encapsulated packets */
	u_int16_t sport;
	/** dest port to use for UDP-encapsulated packets */
	u_int16_t dport;
};

typedef enum policy_dir_t policy_dir_t;

/**
 * Direction of a policy. These are equal to those
 * defined in xfrm.h, but we want to stay implementation
 * neutral here.
 */
enum policy_dir_t {
	/** Policy for inbound traffic */
	POLICY_IN = 0,
	/** Policy for outbound traffic */
	POLICY_OUT = 1,
	/** Policy for forwarded traffic */
	POLICY_FWD = 2,
};

typedef struct kernel_interface_t kernel_interface_t;

/**
 * @brief Interface to the kernel.
 * 
 * The kernel interface handles the communication with the kernel
 * for SA and policy management. It allows setup of these, and provides 
 * further the handling of kernel events.
 * Policy information are cached in the interface. This is necessary to do
 * reference counting. The Linux kernel does not allow the same policy
 * installed twice, but we need this as CHILD_SA exist multiple times
 * when rekeying. Thats why we do reference counting of policies.
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
	status_t (*get_spi)(kernel_interface_t *this, host_t *src, host_t *dst, 
						protocol_id_t protocol, u_int32_t reqid, u_int32_t *spi);
	
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
	 * @param prf_plus		PRF to derive keys from
	 * @param natt			NAT-T Configuration, or NULL of no NAT-T used
	 * @param replace		Should an already installed SA be updated?
	 * @return
	 * 						- SUCCESS
	 * 						- FAILED if kernel comm failed
	 */
	status_t (*add_sa) (kernel_interface_t *this,
						host_t *src, host_t *dst, u_int32_t spi,
						protocol_id_t protocol, u_int32_t reqid,
						u_int64_t expire_soft, u_int64_t expire_hard,
						algorithm_t *enc_alg, algorithm_t *int_alg,
						prf_plus_t *prf_plus, natt_conf_t *natt, bool update);
	
	/**
	 * @brief Update the hosts on an installed SA.
	 *
	 * We cannot directly update the destination address as the kernel
	 * requires the spi, the protocol AND the destination address (and family)
	 * to identify SAs. Therefore if the destination address changed we
	 * create a new SA and delete the old one.
	 *
	 * @param this			calling object
	 * @param dst			destination address for this SA
	 * @param spi			SPI of the SA
	 * @param protocol		protocol for this SA (ESP/AH)
	 * @param new_src		new source address for this SA
	 * @param new_dst		new destination address for this SA
	 * @param src_changes	changes in src
	 * @param dst_changes	changes in dst
	 * @return
	 * 						- SUCCESS
	 * 						- FAILED if kernel comm failed
	 */
	status_t (*update_sa)(kernel_interface_t *this, host_t *dst, u_int32_t spi,
						  protocol_id_t protocol,
						  host_t *new_src, host_t *new_dst,
						  host_diff_t src_changes, host_diff_t dst_changes);
	
	/**
	 * @brief Query the use time of an SA.
	 *
	 * The use time of an SA is not the time of the last usage, but 
	 * the time of the first usage of the SA.
	 * 
	 * @param this			calling object
	 * @param dst			destination address for this SA
	 * @param spi			SPI allocated by us or remote peer
	 * @param protocol		protocol for this SA (ESP/AH)
	 * @param[out] use_time	the time of this SA's last use
	 * @return
	 * 						- SUCCESS
	 * 						- FAILED if kernel comm failed
	 */
	status_t (*query_sa) (kernel_interface_t *this, host_t *dst, u_int32_t spi, 
						  protocol_id_t protocol, u_int32_t *use_time);
	
	/**
	 * @brief Delete a previusly installed SA from the SAD.
	 * 
	 * @param this			calling object
	 * @param dst			destination address for this SA
	 * @param spi			SPI allocated by us or remote peer
	 * @param protocol		protocol for this SA (ESP/AH)
	 * @return
	 * 						- SUCCESS
	 * 						- FAILED if kernel comm failed
	 */
	status_t (*del_sa) (kernel_interface_t *this, host_t *dst, u_int32_t spi,
						protocol_id_t protocol);
	
	/**
	 * @brief Add a policy to the SPD.
	 * 
	 * A policy is always associated to an SA. Traffic which matches a
	 * policy is handled by the SA with the same reqid.
	 * If the update flag is set, the policy is updated with the new
	 * src/dst addresses.
	 * If the update flag is not set, but a such policy is already in the
	 * kernel, the reference count to this policy is increased.
	 * 
	 * @param this			calling object
	 * @param src			source address of SA
	 * @param dst			dest address of SA
	 * @param src_ts		traffic selector to match traffic source
	 * @param dst_ts		traffic selector to match traffic dest
	 * @param direction		direction of traffic, POLICY_IN, POLICY_OUT, POLICY_FWD
	 * @param protocol		protocol to use to protect traffic (AH/ESP)
	 * @param reqid			uniqe ID of an SA to use to enforce policy
	 * @param high_prio		if TRUE, uses a higher priority than any with FALSE
	 * @param update		update an existing policy, if TRUE
	 * @return
	 * 						- SUCCESS
	 * 						- FAILED if kernel comm failed
	 */
	status_t (*add_policy) (kernel_interface_t *this,
							host_t *src, host_t *dst,
							traffic_selector_t *src_ts,
							traffic_selector_t *dst_ts,
							policy_dir_t direction, protocol_id_t protocol,
							u_int32_t reqid, bool high_prio, bool update);
	
	/**
	 * @brief Query the use time of a policy.
	 *
	 * The use time of a policy is the time the policy was used
	 * for the last time.
	 * 
	 * @param this			calling object
	 * @param src_ts		traffic selector to match traffic source
	 * @param dst_ts		traffic selector to match traffic dest
	 * @param direction		direction of traffic, POLICY_IN, POLICY_OUT, POLICY_FWD
	 * @param[out] use_time	the time of this SA's last use
	 * @return
	 * 						- SUCCESS
	 * 						- FAILED if kernel comm failed
	 */
	status_t (*query_policy) (kernel_interface_t *this,
							  traffic_selector_t *src_ts, 
							  traffic_selector_t *dst_ts,
							  policy_dir_t direction, u_int32_t *use_time);
	
	/**
	 * @brief Remove a policy from the SPD.
	 *
	 * The kernel interface implements reference counting for policies.
	 * If the same policy is installed multiple times (in the case of rekeying),
	 * the reference counter is increased. del_policy() decreases the ref counter
	 * and removes the policy only when no more references are available.
	 *
	 * @param this			calling object
	 * @param src_ts		traffic selector to match traffic source
	 * @param dst_ts		traffic selector to match traffic dest
	 * @param direction		direction of traffic, POLICY_IN, POLICY_OUT, POLICY_FWD
	 * @return
	 * 						- SUCCESS
	 * 						- FAILED if kernel comm failed
	 */
	status_t (*del_policy) (kernel_interface_t *this,
							traffic_selector_t *src_ts, 
							traffic_selector_t *dst_ts,
							policy_dir_t direction);
	
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
