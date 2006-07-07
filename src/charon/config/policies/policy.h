/**
 * @file policy.h
 * 
 * @brief Interface of policy_t.
 *  
 */

/*
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

#ifndef POLICY_H_
#define POLICY_H_

#include <types.h>
#include <utils/identification.h>
#include <config/traffic_selector.h>
#include <config/proposal.h>
#include <encoding/payloads/auth_payload.h>


typedef struct policy_t policy_t;

/**
 * @brief A policy_t defines the policies to apply to CHILD_SAs.
 * 
 * The given two IDs identify a policy. These rules define how
 * child SAs may be set up and which traffic may be IPsec'ed.
 * 
 * @b Constructors:
 *   - policy_create()
 * 
 * @ingroup config
 */
struct policy_t {
	
	/**
	 * @brief Get the name of the policy.
	 * 
	 * Returned object is not getting cloned.
	 * 
	 * @param this			calling object
	 * @return				policy's name
	 */
	char *(*get_name) (policy_t *this);
	
	/**
	 * @brief Get own id to use for identification.
	 * 
	 * Returned object is not getting cloned.
	 * 
	 * @param this			calling object
	 * @return				own id
	 */
	identification_t *(*get_my_id) (policy_t *this);
	
	/**
	 * @brief Get id of communication partner.
	 *
	 * Returned object is not getting cloned.
	 * 
	 * @param this			calling object
	 * @return				other id
	 */
	identification_t *(*get_other_id) (policy_t *this);

	/**
	 * @brief Update own ID.
	 * 
	 * It may be necessary to uptdate own ID, as it 
	 * is set to %any or to e.g. *@strongswan.org in 
	 * some cases.
	 * Old ID is destroyed, new one NOT cloned.
	 * 
	 * @param this		calling object
	 * @param my_id		new ID to set as my_id
	 */
	void (*update_my_id) (policy_t *this, identification_t *my_id);

	/**
	 * @brief Update others ID.
	 * 
	 * It may be necessary to uptdate others ID, as it 
	 * is set to %any or to e.g. *@strongswan.org in 
	 * some cases.
	 * Old ID is destroyed, new one NOT cloned.
	 * 
	 * @param this		calling object
	 * @param other_id	new ID to set as other_id
	 */
	void (*update_other_id) (policy_t *this, identification_t *other_id);

	/**
	 * @brief Update own address in traffic selectors.
	 * 
	 * Update own 0.0.0.0 address in traffic selectors
	 * with supplied one. The size of the subnet will be
	 * set to /32.
	 * 
	 * @param this		calling object
	 * @param my_host	new address to set in traffic selectors
	 */
	void (*update_my_ts) (policy_t *this, host_t *my_host);

	/**
	 * @brief Update others address in traffic selectors.
	 * 
	 * Update remote 0.0.0.0 address in traffic selectors
	 * with supplied one. The size of the subnet will be
	 * set to /32.
	 * 
	 * @param this		calling object
	 * @param other_host	new address to set in traffic selectors
	 */
	void (*update_other_ts) (policy_t *this, host_t *other_host);
	
	/**
	 * @brief Get configured traffic selectors for our site.
	 * 
	 * Returns a list with all traffic selectors for the local
	 * site. List and items MUST NOT be freed nor modified.
	 * 
	 * @param this						calling object
	 * @return							list with traffic selectors
	 */
	linked_list_t *(*get_my_traffic_selectors) (policy_t *this);
	
	/**
	 * @brief Get configured traffic selectors for others site.
	 * 
	 * Returns a list with all traffic selectors for the remote
	 * site. List and items MUST NOT be freed nor modified.
	 * 
	 * @param this						calling object
	 * @return							list with traffic selectors
	 */
	linked_list_t *(*get_other_traffic_selectors) (policy_t *this);
	
	/**
	 * @brief Select traffic selectors from a supplied list for local site.
	 * 
	 * Resulted list and traffic selectors must be destroyed after usage.
	 * 
	 * @param this						calling object
	 * @param supplied					linked list with traffic selectors
	 * @return							list containing the selected traffic selectors
	 */
	linked_list_t *(*select_my_traffic_selectors) (policy_t *this, linked_list_t *supplied);
		
	/**
	 * @brief Select traffic selectors from a supplied list for remote site.
	 * 
	 * Resulted list and traffic selectors must be destroyed after usage.
	 * 
	 * @param this						calling object
	 * @param supplied					linked list with traffic selectors
	 * @return							list containing the selected traffic selectors
	 */
	linked_list_t *(*select_other_traffic_selectors) (policy_t *this, linked_list_t *supplied);
	
	/**
	 * @brief Get the list of internally stored proposals.
	 * 
	 * Rembember: policy_t does store proposals for AH/ESP, 
	 * IKE proposals are in the connection_t
	 * 
	 * @warning List and Items are still owned by policy and MUST NOT
	 *			be manipulated or freed!
	 * 
	 * @param this					calling object
	 * @return						lists with proposals
	 */
	linked_list_t *(*get_proposals) (policy_t *this);
	
	/**
	 * @brief Select a proposal from a supplied list.
	 * 
	 * @param this					calling object
	 * @param proposals				list from from wich proposals are selected
	 * @return						selected proposal, or NULL if nothing matches
	 */
	proposal_t *(*select_proposal) (policy_t *this, linked_list_t *proposals);
	
	/**
	 * @brief Add a traffic selector to the list for local site.
	 * 
	 * After add, proposal is owned by policy.
	 * 
	 * @warning Do not add while other threads are reading.
	 * 
	 * @param this					calling object
	 * @param traffic_selector		traffic_selector to add
	 */
	void (*add_my_traffic_selector) (policy_t *this, traffic_selector_t *traffic_selector);
	
	/**
	 * @brief Add a traffic selector to the list for remote site.
	 * 
	 * After add, proposal is owned by policy.
	 * 
	 * @warning Do not add while other threads are reading.
	 * 
	 * @param this					calling object
	 * @param traffic_selector		traffic_selector to add
	 */
	void (*add_other_traffic_selector) (policy_t *this, traffic_selector_t *traffic_selector);
	
	/**
	 * @brief Add a proposal to the list. 
	 * 
	 * The proposals are stored by priority, first added
	 * is the most prefered.
	 * 
	 * @warning Do not add while other threads are reading.
	 * 
	 * @param this					calling object
	 * @param proposal				proposal to add
	 */
	void (*add_proposal) (policy_t *this, proposal_t *proposal);
	
	/**
	 * @brief Add certification authorities
	 * 
	 * @param this					calling object
	 * @param my_ca					issuer of my certificate
	 * @param other_ca				required issuer of the peer's certificate
	 */
	void (*add_authorities) (policy_t *this, identification_t *my_ca, identification_t *other_ca);

	/**
	 * @brief Add updown script
	 * 
	 * @param this					calling object
	 * @param updown				updown script
	 */
	void (*add_updown) (policy_t *this, char *updown);

	/**
	 * @brief Get the lifetime of a policy, before rekeying starts.
	 * 
	 * A call to this function automatically adds a jitter to
	 * avoid simultanous rekeying.
	 * 
	 * @param this				policy 
	 * @return					lifetime in seconds
	 */
	u_int32_t (*get_soft_lifetime) (policy_t *this);
	
	/**
	 * @brief Get the lifetime of a policy, before SA gets deleted.
	 * 
	 * @param this				policy
	 * @return					lifetime in seconds
	 */
	u_int32_t (*get_hard_lifetime) (policy_t *this);
	
	/**
	 * @brief Clone a policy.
	 * 
	 * @param this				policy to clone
	 * @return					clone of it
	 */
	policy_t *(*clone) (policy_t *this);
	
	/**
	 * @brief Destroys the policy object
	 * 
	 * @param this				calling object
	 */
	void (*destroy) (policy_t *this);
};

/**
 * @brief Create a configuration object for IKE_AUTH and later.
 * 
 * name-string gets cloned, ID's not.
 * Lifetimes are in seconds. To prevent to peers to start rekeying at the
 * same time, a jitter may be specified. Rekeying of an SA starts at
 * (soft_lifetime - random(0, jitter)). After a successful rekeying, 
 * the hard_lifetime limit counter is reset. You should specify
 * hard_lifetime > soft_lifetime > jitter.
 * 
 * @param name				name of the policy
 * @param my_id 			identification_t for ourselves
 * @param other_id 			identification_t for the remote guy
 * @param hard_lifetime		lifetime before deleting an SA
 * @param soft_lifetime		lifetime before rekeying an SA
 * @param jitter			range of randomization time
 * @return 					policy_t object
 * 
 * @ingroup config
 */
policy_t *policy_create(char *name, identification_t *my_id, identification_t *other_id,
						u_int32_t hard_lifetime, u_int32_t soft_lifetime, u_int32_t jitter);

#endif /* POLICY_H_ */
