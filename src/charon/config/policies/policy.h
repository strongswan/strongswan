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

typedef enum auth_method_t auth_method_t;

/**
 * AUTH Method to use.
 * 
 * @ingroup config
 */
enum auth_method_t {
	/**
	 * Computed as specified in section 2.15 of RFC using 
	 * an RSA private key over a PKCS#1 padded hash.
	 */
	RSA_DIGITAL_SIGNATURE = 1,
	
	/** 
	 * Computed as specified in section 2.15 of RFC using the 
	 * shared key associated with the identity in the ID payload 
	 * and the negotiated prf function
	 */
	SHARED_KEY_MESSAGE_INTEGRITY_CODE = 2,
	
	/**
	 * Computed as specified in section 2.15 of RFC using a 
	 * DSS private key over a SHA-1 hash.
	 */
	DSS_DIGITAL_SIGNATURE = 3,
};

/**
 * string mappings for auth_method_t.
 * 
 * @ingroup config
 */
extern enum_names auth_method_names;


typedef enum dpd_action_t dpd_action_t;

/**
 * @brief Actions to take when a peer does not respond (dead peer detected).
 *
 * These values are the same as in pluto/starter, so do not modify them!
 *
 * @ingroup config
 */
enum dpd_action_t {
	/** DPD disabled */
	DPD_NONE,
	/** remove CHILD_SA without replacement */
	DPD_CLEAR,
	/** route the CHILD_SA to resetup when needed */
	DPD_ROUTE,
	/** restart CHILD_SA in a new IKE_SA, immediately */
	DPD_RESTART,
};

/**
 * String mappings for dpd_action_t.
 */
extern enum_names dpd_action_names;


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
	 * @brief Get the authentication method to use.
	 * 
	 * @param this		calling object
	 * @return			authentication method
	 */
	auth_method_t (*get_auth_method) (policy_t *this);
	
	/**
	 * @brief Get configured traffic selectors for our site.
	 * 
	 * Returns a list with all traffic selectors for the local
	 * site. List and items must be destroyed after usage.
	 * 
	 * @param this			calling object
	 * @return				list with traffic selectors
	 */
	linked_list_t *(*get_my_traffic_selectors) (policy_t *this, host_t *me);
	
	/**
	 * @brief Get configured traffic selectors for others site.
	 * 
	 * Returns a list with all traffic selectors for the remote
	 * site. List and items must be destroyed after usage.
	 * 
	 * @param this			calling object
	 * @return				list with traffic selectors
	 */
	linked_list_t *(*get_other_traffic_selectors) (policy_t *this, host_t* other);
	
	/**
	 * @brief Select traffic selectors from a supplied list for local site.
	 * 
	 * Resulted list and traffic selectors must be destroyed after usage.
	 * As the traffic selectors may contain a wildcard address (0.0.0.0) for
	 * addresses we don't know in previous, an address may be supplied to
	 * replace these 0.0.0.0 addresses on-the-fly.
	 * 
	 * @param this			calling object
	 * @param supplied		linked list with traffic selectors
	 * @param me			host address used by us
	 * @return				list containing the selected traffic selectors
	 */
	linked_list_t *(*select_my_traffic_selectors) (policy_t *this, 
												   linked_list_t *supplied,
												   host_t *me);
		
	/**
	 * @brief Select traffic selectors from a supplied list for remote site.
	 * 
	 * Resulted list and traffic selectors must be destroyed after usage.
	 * As the traffic selectors may contain a wildcard address (0.0.0.0) for
	 * addresses we don't know in previous, an address may be supplied to
	 * replace these 0.0.0.0 addresses on-the-fly.
	 *
	 * @param this			calling object
	 * @param supplied		linked list with traffic selectors
	 * @return				list containing the selected traffic selectors
	 */
	linked_list_t *(*select_other_traffic_selectors) (policy_t *this, 
													  linked_list_t *supplied,
													  host_t *other);
	
	/**
	 * @brief Get the list of internally stored proposals.
	 * 
	 * policy_t does store proposals for AH/ESP, IKE proposals are in 
	 * the connection_t.
	 * Resulting list and all of its proposals must be freed after usage.
	 *
	 * @param this			calling object
	 * @return				lists with proposals
	 */
	linked_list_t *(*get_proposals) (policy_t *this);
	
	/**
	 * @brief Select a proposal from a supplied list.
	 *
	 * Returned propsal is newly created and must be destroyed after usage.
	 * 
	 * @param this			calling object
	 * @param proposals		list from from wich proposals are selected
	 * @return				selected proposal, or NULL if nothing matches
	 */
	proposal_t *(*select_proposal) (policy_t *this, linked_list_t *proposals);
	
	/**
	 * @brief Add a traffic selector to the list for local site.
	 * 
	 * After add, traffic selector is owned by policy.
	 * 
	 * @param this				calling object
	 * @param traffic_selector	traffic_selector to add
	 */
	void (*add_my_traffic_selector) (policy_t *this, traffic_selector_t *traffic_selector);
	
	/**
	 * @brief Add a traffic selector to the list for remote site.
	 * 
	 * After add, traffic selector is owned by policy.
	 * 
	 * @param this				calling object
	 * @param traffic_selector	traffic_selector to add
	 */
	void (*add_other_traffic_selector) (policy_t *this, traffic_selector_t *traffic_selector);
	
	/**
	 * @brief Add a proposal to the list. 
	 * 
	 * The proposals are stored by priority, first added
	 * is the most prefered.
	 * After add, proposal is owned by policy.
	 * 
	 * @param this			calling object
	 * @param proposal		proposal to add
	 */
	void (*add_proposal) (policy_t *this, proposal_t *proposal);
	
	/**
	 * @brief Add certification authorities.
	 * 
	 * @param this			calling object
	 * @param my_ca			issuer of my certificate
	 * @param other_ca		required issuer of the peer's certificate
	 */
	void (*add_authorities) (policy_t *this, identification_t *my_ca, identification_t *other_ca);

	/**
	 * @brief Get updown script
	 * 
	 * @param this			calling object
	 * @return				path to updown script
	 */
	char* (*get_updown) (policy_t *this);
	
	/**
	 * @brief Get hostaccess flag
	 * 
	 * @param this			calling object
	 * @return				value of hostaccess flag
	 */
	bool (*get_hostaccess) (policy_t *this);
	
	/**
	 * @brief What should be done with a CHILD_SA, when other peer does not respond.
	 *
	 * @param this 		calling object
	 * @return			dpd action
	 */	
	dpd_action_t (*get_dpd_action) (policy_t *this);

	/**
	 * @brief Get the lifetime of a policy, before rekeying starts.
	 * 
	 * A call to this function automatically adds a jitter to
	 * avoid simultanous rekeying.
	 * 
	 * @param this			policy 
	 * @return				lifetime in seconds
	 */
	u_int32_t (*get_soft_lifetime) (policy_t *this);
	
	/**
	 * @brief Get the lifetime of a policy, before SA gets deleted.
	 * 
	 * @param this			policy
	 * @return				lifetime in seconds
	 */
	u_int32_t (*get_hard_lifetime) (policy_t *this);
	
	/**
	 * @brief Get a new reference.
	 *
	 * Get a new reference to this policy by increasing
	 * it's internal reference counter.
	 * Do not call get_ref or any other function until you
	 * already have a reference. Otherwise the object may get
	 * destroyed while calling get_ref(),
	 * 
	 * @param this				calling object
	 */
	void (*get_ref) (policy_t *this);
	
	/**
	 * @brief Destroys the policy object.
	 *
	 * Decrements the internal reference counter and
	 * destroys the policy when it reaches zero.
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
 * After a call to create, a reference is obtained (refcount = 1).
 * 
 * @param name				name of the policy
 * @param my_id 			identification_t for ourselves
 * @param other_id 			identification_t for the remote guy
 * @param auth_method		Authentication method to use for our(!) auth data
 * @param hard_lifetime		lifetime before deleting an SA
 * @param soft_lifetime		lifetime before rekeying an SA
 * @param jitter			range of randomization time
 * @param updown			updown script to execute on up/down event
 * @param hostaccess		allow access to the host itself (used by the updown script)
 * @param dpd_action		what to to with a CHILD_SA when other peer does not respond
 * @return 					policy_t object
 * 
 * @ingroup config
 */
policy_t *policy_create(char *name, 
						identification_t *my_id, identification_t *other_id,
						auth_method_t auth_method,
						u_int32_t hard_lifetime, u_int32_t soft_lifetime,
						u_int32_t jitter,
						char *updown, bool hostaccess,
						dpd_action_t dpd_action);

#endif /* POLICY_H_ */
