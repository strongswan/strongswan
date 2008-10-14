/*
 * Copyright (C) 2006-2008 Tobias Brunner
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
 *
 * $Id$
 */

/**
 * @defgroup kernel_ipsec kernel_ipsec
 * @{ @ingroup kernel
 */

#ifndef KERNEL_IPSEC_H_
#define KERNEL_IPSEC_H_

typedef enum ipsec_mode_t ipsec_mode_t;
typedef enum policy_dir_t policy_dir_t;
typedef struct kernel_ipsec_t kernel_ipsec_t;

#include <utils/host.h>
#include <crypto/prf_plus.h>
#include <encoding/payloads/proposal_substructure.h>

/**
 * Mode of an CHILD_SA.
 *
 * These are equal to those defined in XFRM, so don't change.
 */
enum ipsec_mode_t {
	/** transport mode, no inner address */
	MODE_TRANSPORT = 0,
	/** tunnel mode, inner and outer addresses */
	MODE_TUNNEL = 1,
	/** BEET mode, tunnel mode but fixed, bound inner addresses */
	MODE_BEET = 4,
};

/**
 * enum names for ipsec_mode_t.
 */
extern enum_name_t *ipsec_mode_names;

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

/**
 * enum names for policy_dir_t.
 */
extern enum_name_t *policy_dir_names;

/**
 * Interface to the ipsec subsystem of the kernel.
 * 
 * The kernel ipsec interface handles the communication with the kernel
 * for SA and policy management. It allows setup of these, and provides 
 * further the handling of kernel events.
 * Policy information are cached in the interface. This is necessary to do
 * reference counting. The Linux kernel does not allow the same policy
 * installed twice, but we need this as CHILD_SA exist multiple times
 * when rekeying. Thats why we do reference counting of policies.
 */
struct kernel_ipsec_t {
	
	/**
	 * Get a SPI from the kernel.
	 *
	 * @warning get_spi() implicitly creates an SA with
	 * the allocated SPI, therefore the replace flag
	 * in add_sa() must be set when installing this SA.
	 * 
	 * @param src		source address of SA
	 * @param dst		destination address of SA
	 * @param protocol	protocol for SA (ESP/AH)
	 * @param reqid		unique ID for this SA
	 * @param spi		allocated spi
	 * @return				SUCCESS if operation completed
	 */
	status_t (*get_spi)(kernel_ipsec_t *this, host_t *src, host_t *dst, 
						protocol_id_t protocol, u_int32_t reqid, u_int32_t *spi);
	
	/**
	 * Get a Compression Parameter Index (CPI) from the kernel.
	 * 
	 * @param src		source address of SA
	 * @param dst		destination address of SA
	 * @param reqid		unique ID for the corresponding SA
	 * @param cpi		allocated cpi
	 * @return				SUCCESS if operation completed
	 */
	status_t (*get_cpi)(kernel_ipsec_t *this, host_t *src, host_t *dst, 
						u_int32_t reqid, u_int16_t *cpi);
	
	/**
	 * Add an SA to the SAD.
	 * 
	 * add_sa() may update an already allocated
	 * SPI (via get_spi). In this case, the replace
	 * flag must be set.
	 * This function does install a single SA for a
	 * single protocol in one direction. The kernel-interface
	 * gets the keys itself from the PRF, as we don't know
	 * his algorithms and key sizes.
	 * 
	 * @param src			source address for this SA
	 * @param dst			destination address for this SA
	 * @param spi			SPI allocated by us or remote peer
	 * @param protocol		protocol for this SA (ESP/AH)
	 * @param reqid			unique ID for this SA
	 * @param expire_soft	lifetime in seconds before rekeying
	 * @param expire_hard	lifetime in seconds before delete
	 * @param enc_alg		Algorithm to use for encryption (ESP only)
	 * @param enc_size		key length of encryption algorithm, if dynamic
	 * @param int_alg		Algorithm to use for integrity protection
	 * @param int_size		key length of integrity algorithm, if dynamic
	 * @param prf_plus		PRF to derive keys from
	 * @param mode			mode of the SA (tunnel, transport)
	 * @param ipcomp		IPComp transform to use
	 * @param encap			enable UDP encapsulation for NAT traversal
	 * @param replace		Should an already installed SA be updated?
	 * @return				SUCCESS if operation completed
	 */
	status_t (*add_sa) (kernel_ipsec_t *this,
						host_t *src, host_t *dst, u_int32_t spi,
						protocol_id_t protocol, u_int32_t reqid,
						u_int64_t expire_soft, u_int64_t expire_hard,
					    u_int16_t enc_alg, u_int16_t enc_size,
					    u_int16_t int_alg, u_int16_t int_size,
						prf_plus_t *prf_plus, ipsec_mode_t mode,
						u_int16_t ipcomp, bool encap,
						bool update);
	
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
	 * @param src			current source address
	 * @param dst			current destination address
	 * @param new_src		new source address
	 * @param new_dst		new destination address
	 * @param encap			use UDP encapsulation
	 * @return				SUCCESS if operation completed
	 */
	status_t (*update_sa)(kernel_ipsec_t *this,
						  u_int32_t spi, protocol_id_t protocol,
						  host_t *src, host_t *dst, 
						  host_t *new_src, host_t *new_dst, bool encap);
	
	/**
	 * Delete a previusly installed SA from the SAD.
	 * 
	 * @param dst			destination address for this SA
	 * @param spi			SPI allocated by us or remote peer
	 * @param protocol		protocol for this SA (ESP/AH)
	 * @return				SUCCESS if operation completed
	 */
	status_t (*del_sa) (kernel_ipsec_t *this, host_t *dst, u_int32_t spi,
						protocol_id_t protocol);
	
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
	 * @param direction		direction of traffic, POLICY_IN, POLICY_OUT, POLICY_FWD
	 * @param protocol		protocol to use to protect traffic (AH/ESP)
	 * @param reqid			unique ID of an SA to use to enforce policy
	 * @param high_prio		if TRUE, uses a higher priority than any with FALSE
	 * @param mode			mode of SA (tunnel, transport)
	 * @param ipcomp		the IPComp transform used
	 * @return				SUCCESS if operation completed
	 */
	status_t (*add_policy) (kernel_ipsec_t *this,
							host_t *src, host_t *dst,
							traffic_selector_t *src_ts,
							traffic_selector_t *dst_ts,
							policy_dir_t direction, protocol_id_t protocol,
							u_int32_t reqid, bool high_prio, ipsec_mode_t mode,
							u_int16_t ipcomp);
	
	/**
	 * Query the use time of a policy.
	 *
	 * The use time of a policy is the time the policy was used
	 * for the last time.
	 * 
	 * @param src_ts		traffic selector to match traffic source
	 * @param dst_ts		traffic selector to match traffic dest
	 * @param direction		direction of traffic, POLICY_IN, POLICY_OUT, POLICY_FWD
	 * @param[out] use_time	the time of this SA's last use
	 * @return				SUCCESS if operation completed
	 */
	status_t (*query_policy) (kernel_ipsec_t *this,
							  traffic_selector_t *src_ts, 
							  traffic_selector_t *dst_ts,
							  policy_dir_t direction, u_int32_t *use_time);
	
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
	 * @param direction		direction of traffic, POLICY_IN, POLICY_OUT, POLICY_FWD
	 * @return				SUCCESS if operation completed
	 */
	status_t (*del_policy) (kernel_ipsec_t *this,
							traffic_selector_t *src_ts, 
							traffic_selector_t *dst_ts,
							policy_dir_t direction);
	
	/**
	 * Destroy the implementation.
	 */
	void (*destroy) (kernel_ipsec_t *this);
};

#endif /* KERNEL_IPSEC_H_ @} */
