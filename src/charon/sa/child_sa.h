/*
 * Copyright (C) 2006-2007 Martin Willi
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
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
 * @defgroup child_sa child_sa
 * @{ @ingroup sa
 */

#ifndef CHILD_SA_H_
#define CHILD_SA_H_

typedef enum child_sa_state_t child_sa_state_t;
typedef struct child_sa_t child_sa_t;

#include <library.h>
#include <crypto/prf_plus.h>
#include <encoding/payloads/proposal_substructure.h>
#include <config/proposal.h>
#include <config/child_cfg.h>

/**
 * States of a CHILD_SA
 */
enum child_sa_state_t {
	
	/**
	 * Just created, uninstalled CHILD_SA
	 */
	CHILD_CREATED,
	
	/**
	 * Installed SPD, but no SAD entries
	 */
	CHILD_ROUTED,
	
	/**
	 * Installed an in-use CHILD_SA
	 */
	CHILD_INSTALLED,
	
	/**
	 * CHILD_SA which is rekeying
	 */
	CHILD_REKEYING,
	
	/**
	 * CHILD_SA in progress of delete
	 */
	CHILD_DELETING,
};

/**
 * enum strings for child_sa_state_t.
 */
extern enum_name_t *child_sa_state_names;

/**
 * Represents an IPsec SAs between two hosts.
 * 
 * A child_sa_t contains two SAs. SAs for both
 * directions are managed in one child_sa_t object. Both
 * SAs and the policies have the same reqid.
 * 
 * The procedure for child sa setup is as follows:
 * - A gets SPIs for a proposal via child_sa_t.alloc
 * - A send the updated proposal to B
 * - B selects a suitable proposal
 * - B calls child_sa_t.add to add and update the selected proposal
 * - B sends the updated proposal to A
 * - A calls child_sa_t.update to update the already allocated SPIs with the chosen proposal
 * 
 * Once SAs are set up, policies can be added using add_policies.
 */
struct child_sa_t {
	
	/**
	 * Get the name of the config this CHILD_SA uses.
	 *
	 * @return			name
	 */
	char* (*get_name) (child_sa_t *this);
	
	/**
	 * Get the reqid of the CHILD SA.
	 * 
	 * Every CHILD_SA has a reqid. The kernel uses this ID to
	 * identify it.
	 *
	 * @return 			reqid of the CHILD SA
	 */
	u_int32_t (*get_reqid)(child_sa_t *this);
	
	/**
	 * Get the SPI of this CHILD_SA.
	 * 
	 * Set the boolean parameter inbound to TRUE to
	 * get the SPI for which we receive packets, use
	 * FALSE to get those we use for sending packets.
	 *
	 * @param inbound	TRUE to get inbound SPI, FALSE for outbound.
	 * @return 			spi of the CHILD SA
	 */
	u_int32_t (*get_spi) (child_sa_t *this, bool inbound);
	
	/**
	 * Get the protocol which this CHILD_SA uses to protect traffic.
	 *
	 * @return 			AH | ESP
	 */
	protocol_id_t (*get_protocol) (child_sa_t *this);
	
	/**
	 * Get info and statistics about this CHILD_SA.
	 *
	 * @param mode		mode this IKE_SA uses
	 * @param encr_algo	encryption algorithm used by this CHILD_SA.
	 * @param encr_len	key length of the algorithm, if any
	 * @param int_algo	integrity algorithm used by this CHILD_SA
	 * @param int_len	key length of the algorithm, if any
	 * @param rekey		time when rekeying is scheduled
	 * @param use_in	time when last traffic was seen coming in
	 * @param use_out	time when last traffic was seen going out
	 * @param use_fwd	time when last traffic was getting forwarded
	 */
	void (*get_stats)(child_sa_t *this, mode_t *mode,
					  encryption_algorithm_t *encr, size_t *encr_len,
					  integrity_algorithm_t *int_algo, size_t *int_len,
					  u_int32_t *rekey, u_int32_t *use_in, u_int32_t *use_out,
					  u_int32_t *use_fwd);
	
	/**
	 * Allocate SPIs for given proposals.
	 * 
	 * Since the kernel manages SPIs for us, we need
	 * to allocate them. If a proposal contains more
	 * than one protocol, for each protocol an SPI is
	 * allocated. SPIs are stored internally and written
	 * back to the proposal.
	 *
	 * @param proposals	list of proposals for which SPIs are allocated
	 */
	status_t (*alloc)(child_sa_t *this, linked_list_t* proposals);
	
	/**
	 * Install the kernel SAs for a proposal, without previous SPI allocation.
	 *
	 * @param proposal	proposal for which SPIs are allocated
	 * @param mode		mode for the CHILD_SA
	 * @param prf_plus	key material to use for key derivation
	 * @return			SUCCESS or FAILED
	 */
	status_t (*add)(child_sa_t *this, proposal_t *proposal, mode_t mode,
					prf_plus_t *prf_plus);
	
	/**
	 * Install the kernel SAs for a proposal, after SPIs have been allocated.
	 *
	 * Updates an SA, for which SPIs are already allocated via alloc().
	 *
	 * @param proposal	proposal for which SPIs are allocated
	 * @param mode		mode for the CHILD_SA
	 * @param prf_plus	key material to use for key derivation
	 * @return			SUCCESS or FAILED
	 */
	status_t (*update)(child_sa_t *this, proposal_t *proposal, mode_t mode,
					   prf_plus_t *prf_plus);

	/**
	 * Update the hosts in the kernel SAs and policies.
	 *
	 * The CHILD must be INSTALLED to do this update.
	 *
	 * @param me		the new local host
	 * @param other		the new remote host
	 * @param			TRUE to use UDP encapsulation for NAT traversal
	 * @return			SUCCESS or FAILED
	 */
	status_t (*update_hosts)(child_sa_t *this, host_t *me, host_t *other,
							 bool encap);
	
	/**
	 * Install the policies using some traffic selectors.
	 *
	 * Supplied lists of traffic_selector_t's specify the policies
	 * to use for this child sa.
	 *
	 * @param my_ts		traffic selectors for local site
	 * @param other_ts	traffic selectors for remote site
	 * @param mode		mode for the SA: tunnel/transport
	 * @return			SUCCESS or FAILED
	 */	
	status_t (*add_policies)(child_sa_t *this, linked_list_t *my_ts_list,
							 linked_list_t *other_ts_list, mode_t mode);
	
	/**
	 * Get the traffic selectors of added policies of local host.
	 *
	 * @param local		TRUE for own traffic selectors, FALSE for remote
	 * @return			list of traffic selectors
	 */	
	linked_list_t* (*get_traffic_selectors) (child_sa_t *this, bool local);
	
	/**
	 * Get the time of this child_sa_t's last use (i.e. last use of any of its policies)
	 * 
	 * @param inbound	query for in- or outbound usage
	 * @param use_time	the time
	 * @return			SUCCESS or FAILED
	 */	
	status_t (*get_use_time) (child_sa_t *this, bool inbound, time_t *use_time);
	
	/**
	 * Get the state of the CHILD_SA.
	 */	
	child_sa_state_t (*get_state) (child_sa_t *this);
	
	/**
	 * Set the state of the CHILD_SA.
	 *
	 * @param state		state to set on CHILD_SA
	 */	
	void (*set_state) (child_sa_t *this, child_sa_state_t state);
	
	/**
	 * Get the config used to set up this child sa.
	 *
	 * @return			child_cfg
	 */
	child_cfg_t* (*get_config) (child_sa_t *this);
	
	/**
	 * Set the virtual IP used received from IRAS.
	 *
	 * To allow proper setup of firewall rules, the virtual IP is required
	 * for filtering.
	 *
	 * @param ip		own virtual IP
	 */
	void (*set_virtual_ip) (child_sa_t *this, host_t *ip);
	
	/**
	 * Destroys a child_sa.
	 */
	void (*destroy) (child_sa_t *this);
};

/**
 * Constructor to create a new child_sa_t.
 *
 * @param me			own address
 * @param other			remote address
 * @param my_id			id of own peer
 * @param other_id		id of remote peer
 * @param config		config to use for this CHILD_SA
 * @param reqid			reqid of old CHILD_SA when rekeying, 0 otherwise
 * @param encap			TRUE to enable UDP encapsulation (NAT traversal)
 * @return				child_sa_t object
 */
child_sa_t * child_sa_create(host_t *me, host_t *other,
							 identification_t *my_id, identification_t* other_id,
							 child_cfg_t *config, u_int32_t reqid, bool encap);

#endif /*CHILD_SA_H_ @} */
