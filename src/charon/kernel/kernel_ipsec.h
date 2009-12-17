/*
 * Copyright (C) 2006-2009 Tobias Brunner
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
#include <config/proposal.h>
#include <config/child_cfg.h>

/**
 * Mode of a CHILD_SA.
 */
enum ipsec_mode_t {
	/** transport mode, no inner address */
	MODE_TRANSPORT = 1,
	/** tunnel mode, inner and outer addresses */
	MODE_TUNNEL,
	/** BEET mode, tunnel mode but fixed, bound inner addresses */
	MODE_BEET,
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
	 * single protocol in one direction.
	 *
	 * @param src			source address for this SA
	 * @param dst			destination address for this SA
	 * @param spi			SPI allocated by us or remote peer
	 * @param protocol		protocol for this SA (ESP/AH)
	 * @param reqid			unique ID for this SA
	 * @param lifetime		lifetime_cfg_t for this SA
	 * @param enc_alg		Algorithm to use for encryption (ESP only)
	 * @param enc_key		key to use for encryption
	 * @param int_alg		Algorithm to use for integrity protection
	 * @param int_key		key to use for integrity protection
	 * @param mode			mode of the SA (tunnel, transport)
	 * @param ipcomp		IPComp transform to use
	 * @param cpi			CPI for IPComp
	 * @param encap			enable UDP encapsulation for NAT traversal
	 * @param inbound		TRUE if this is an inbound SA
	 * @param src_ts		traffic selector with BEET source address
	 * @param dst_ts		traffic selector with BEET destination address
	 * @return				SUCCESS if operation completed
	 */
	status_t (*add_sa) (kernel_ipsec_t *this,
						host_t *src, host_t *dst, u_int32_t spi,
						protocol_id_t protocol, u_int32_t reqid,
						lifetime_cfg_t *lifetime,
						u_int16_t enc_alg, chunk_t enc_key,
						u_int16_t int_alg, chunk_t int_key,
						ipsec_mode_t mode, u_int16_t ipcomp, u_int16_t cpi,
						bool encap, bool inbound,
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
	 * @return				SUCCESS if operation completed, NOT_SUPPORTED if
	 *					  the kernel interface can't update the SA
	 */
	status_t (*update_sa)(kernel_ipsec_t *this,
						  u_int32_t spi, protocol_id_t protocol, u_int16_t cpi,
						  host_t *src, host_t *dst,
						  host_t *new_src, host_t *new_dst,
						  bool encap, bool new_encap);

	/**
	 * Query the number of bytes processed by an SA from the SAD.
	 *
	 * @param src			source address for this SA
	 * @param dst			destination address for this SA
	 * @param spi			SPI allocated by us or remote peer
	 * @param protocol		protocol for this SA (ESP/AH)
	 * @param[out] bytes	the number of bytes processed by SA
	 * @return				SUCCESS if operation completed
	 */
	status_t (*query_sa) (kernel_ipsec_t *this, host_t *src, host_t *dst,
						  u_int32_t spi, protocol_id_t protocol, u_int64_t *bytes);

	/**
	 * Delete a previusly installed SA from the SAD.
	 *
	 * @param src			source address for this SA
	 * @param dst			destination address for this SA
	 * @param spi			SPI allocated by us or remote peer
	 * @param protocol		protocol for this SA (ESP/AH)
	 * @param cpi			CPI for IPComp or 0
	 * @return				SUCCESS if operation completed
	 */
	status_t (*del_sa) (kernel_ipsec_t *this, host_t *src, host_t *dst,
						u_int32_t spi, protocol_id_t protocol, u_int16_t cpi);

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
	 * @param spi			SPI of SA
	 * @param protocol		protocol to use to protect traffic (AH/ESP)
	 * @param reqid			unique ID of an SA to use to enforce policy
	 * @param mode			mode of SA (tunnel, transport)
	 * @param ipcomp		the IPComp transform used
	 * @param cpi			CPI for IPComp
	 * @param routed		TRUE, if this policy is routed in the kernel
	 * @return				SUCCESS if operation completed
	 */
	status_t (*add_policy) (kernel_ipsec_t *this,
							host_t *src, host_t *dst,
							traffic_selector_t *src_ts,
							traffic_selector_t *dst_ts,
							policy_dir_t direction, u_int32_t spi,
							protocol_id_t protocol, u_int32_t reqid,
							ipsec_mode_t mode, u_int16_t ipcomp, u_int16_t cpi,
							bool routed);

	/**
	 * Query the use time of a policy.
	 *
	 * The use time of a policy is the time the policy was used for the last
	 * time. It is not the system time, but a monotonic timestamp as returned
	 * by time_monotonic.
	 *
	 * @param src_ts		traffic selector to match traffic source
	 * @param dst_ts		traffic selector to match traffic dest
	 * @param direction		direction of traffic, POLICY_IN, POLICY_OUT, POLICY_FWD
	 * @param[out] use_time	the monotonic timestamp of this SA's last use
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
	 * @param unrouted		TRUE, if this policy is unrouted from the kernel
	 * @return				SUCCESS if operation completed
	 */
	status_t (*del_policy) (kernel_ipsec_t *this,
							traffic_selector_t *src_ts,
							traffic_selector_t *dst_ts,
							policy_dir_t direction,
							bool unrouted);

	/**
	 * Destroy the implementation.
	 */
	void (*destroy) (kernel_ipsec_t *this);
};

#endif /** KERNEL_IPSEC_H_ @}*/
