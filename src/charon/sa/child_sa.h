/**
 * @file child_sa.h
 *
 * @brief Interface of child_sa_t.
 *
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
 * Copyright (C) 2006 Martin Willi
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


#ifndef CHILD_SA_H_
#define CHILD_SA_H_

#include <types.h>
#include <crypto/prf_plus.h>
#include <encoding/payloads/proposal_substructure.h>
#include <config/proposal.h>
#include <utils/logger.h>

/**
 * Where we should start with reqid enumeration
 */
#define REQID_START 2000000000

typedef enum child_sa_state_t child_sa_state_t;

/**
 * @brief States of a CHILD_SA
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
 * String mappings for child_sa_state_t.
 */
extern mapping_t child_sa_state_m[];

typedef struct child_sa_t child_sa_t;

/**
 * @brief Represents an IPsec SAs between two hosts.
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
 * 
 * 
 * @b Constructors:
 *  - child_sa_create()
 * 
 * @ingroup sa
 */
struct child_sa_t {
	
	/**
	 * @brief Get the name of the policy this CHILD_SA uses.
	 *
	 * @param this			calling object
	 * @return				name
	 */
	char* (*get_name) (child_sa_t *this);
	
	/**
	 * @brief Set the name of the policy this IKE_SA uses.
	 *
	 * @param this			calling object
	 * @param name			name, gets cloned
	 */
	void (*set_name) (child_sa_t *this, char* name);
	
	/**
	 * @brief Get the unique reqid of the CHILD SA.
	 * 
	 * Every CHILD_SA has a unique reqid, which is also 
	 * stored down in the kernel.
	 *
	 * @param this 		calling object
	 * @return 			reqid of the CHILD SA
	 */
	u_int32_t (*get_reqid)(child_sa_t *this);
	
	/**
	 * @brief Get the SPI of this CHILD_SA.
	 * 
	 * Set the boolean parameter inbound to TRUE to
	 * get the SPI for which we receive packets, use
	 * FALSE to get those we use for sending packets.
	 *
	 * @param this 		calling object
	 * @param inbound	TRUE to get inbound SPI, FALSE for outbound.
	 * @return 			spi of the CHILD SA
	 */
	u_int32_t (*get_spi) (child_sa_t *this, bool inbound);
	
	/**
	 * @brief Get the protocol which this CHILD_SA uses to protect traffic.
	 *
	 * @param this 		calling object
	 * @return 			AH | ESP
	 */
	protocol_id_t (*get_protocol) (child_sa_t *this);
	
	/**
	 * @brief Allocate SPIs for given proposals.
	 * 
	 * Since the kernel manages SPIs for us, we need
	 * to allocate them. If a proposal contains more
	 * than one protocol, for each protocol an SPI is
	 * allocated. SPIs are stored internally and written
	 * back to the proposal.
	 *
	 * @param this 		calling object
	 * @param proposals	list of proposals for which SPIs are allocated
	 */
	status_t (*alloc)(child_sa_t *this, linked_list_t* proposals);
	
	/**
	 * @brief Install the kernel SAs for a proposal, without previous SPI allocation.
	 *
	 * @param this 		calling object
	 * @param proposal	proposal for which SPIs are allocated
	 * @param prf_plus	key material to use for key derivation
	 * @return			SUCCESS or FAILED
	 */
	status_t (*add)(child_sa_t *this, proposal_t *proposal, prf_plus_t *prf_plus);
	
	/**
	 * @brief Install the kernel SAs for a proposal, after SPIs have been allocated.
	 *
	 * Updates an SA, for which SPIs are already allocated via alloc().
	 *
	 * @param this 		calling object
	 * @param proposal	proposal for which SPIs are allocated
	 * @param prf_plus	key material to use for key derivation
	 * @return			SUCCESS or FAILED
	 */
	status_t (*update)(child_sa_t *this, proposal_t *proposal, prf_plus_t *prf_plus);

	/**
	 * @brief Update the hosts in the kernel SAs and policies
	 *
	 * @warning only call this after update() has been called.
	 *
	 * @param this			calling object
	 * @param new_me		the new local host
	 * @param new_other		the new remote host
	 * @param my_diff		differences to apply for me
	 * @param other_diff	differences to apply for other
	 * @return				SUCCESS or FAILED
	 */
	status_t (*update_hosts)(child_sa_t *this, host_t *new_me, host_t *new_other,
							 host_diff_t my_diff, host_diff_t other_diff);
	
	/**
	 * @brief Install the policies using some traffic selectors.
	 *
	 * Supplied lists of traffic_selector_t's specify the policies
	 * to use for this child sa.
	 *
	 * @param this 		calling object
	 * @param my_ts		traffic selectors for local site
	 * @param other_ts	traffic selectors for remote site
	 * @return			SUCCESS or FAILED
	 */	
	status_t (*add_policies)(child_sa_t *this, 
							 linked_list_t *my_ts_list,
							 linked_list_t *other_ts_list);
	
	/**
	 * @brief Get the traffic selectors of added policies of local host.
	 *
	 * @param this 		calling object
	 * @return			list of traffic selectors
	 */	
	linked_list_t* (*get_my_traffic_selectors) (child_sa_t *this);
	
	/**
	 * @brief Get the traffic selectors of added policies of remote host.
	 *
	 * @param this 		calling object
	 * @return			list of traffic selectors
	 */	
	linked_list_t* (*get_other_traffic_selectors) (child_sa_t *this);
	
	/**
	 * @brief Get the time of this child_sa_t's last use (i.e. last use of any of its policies)
	 * 
	 * @param this 		calling object
	 * @param inbound	query for in- or outbound usage
	 * @param use_time	the time
	 * @return			SUCCESS or FAILED
	 */	
	status_t (*get_use_time) (child_sa_t *this, bool inbound, time_t *use_time);
	
	/**
	 * @brief Get the state of the CHILD_SA.
	 *
	 * @param this 		calling object
	 */	
	child_sa_state_t (*get_state) (child_sa_t *this);
	
	/**
	 * @brief Set the state of the CHILD_SA.
	 *
	 * @param this 		calling object
	 */	
	void (*set_state) (child_sa_t *this, child_sa_state_t state);
	
	/**
	 * @brief Set the transaction which rekeys this CHILD_SA.
	 *
	 * Since either end may initiate CHILD_SA rekeying, we must detect
	 * such situations to handle them cleanly. A rekeying transaction
	 * registers itself to the CHILD_SA, and checks later if another
	 * transaction is in progress of a rekey.
	 * 
	 * @todo Fix include problematics to allow inclusion of 
	 * the create_child_sa_t transaction.
	 *
	 * @param this 		calling object
	 */	
	void (*set_rekeying_transaction) (child_sa_t *this, void *transaction);
	
	/**
	 * @brief Get the transaction which rekeys this CHILD_SA.
	 *
	 * @see set_rekeying_transactoin().
	 *
	 * @param this 		calling object
	 */	
	void* (*get_rekeying_transaction) (child_sa_t *this);
	
	/**
	 * @brief Log the status of a child_sa to a logger.
	 *
	 * The status of ESP/AH SAs is logged with the supplied logger in
	 * a human readable form.
	 * Supplying NULL as logger uses the internal child_sa logger
	 * to do the logging.
	 *
	 * @param this 		calling object
	 * @param logger	logger to use for logging
	 */	
	void (*log_status) (child_sa_t *this, logger_t *logger);
	
	/**
	 * @brief Destroys a child_sa.
	 *
	 * @param this 		calling object
	 */
	void (*destroy) (child_sa_t *this);
};

/**
 * @brief Constructor to create a new child_sa_t.
 *
 * @param rekey_reqid	reqid of old CHILD_SA when rekeying, 0 otherwise
 * @param me			own address
 * @param other			remote address
 * @param my_id			id of own peer
 * @param other_id		id of remote peer
 * @param soft_lifetime	time before rekeying
 * @param hard_lifteime	time before delete
 * @param script		updown script to use when calling child_sa_t.script()
 * @param hostaccess	allow host access (needed by updown script)
 * @param use_natt		TRUE if NAT traversal is used
 * @return				child_sa_t object
 * 
 * @ingroup sa
 */
child_sa_t * child_sa_create(u_int32_t rekey_reqid, host_t *me, host_t *other,
							 identification_t *my_id, identification_t* other_id,
							 u_int32_t soft_lifetime, u_int32_t hard_lifetime,
							 char *script, bool hostaccess, bool use_natt);

#endif /*CHILD_SA_H_*/
