/**
 * @file ike_cfg.h
 *
 * @brief Interface of ike_cfg_t.
 *
 */

/*
 * Copyright (C) 2005-2007 Martin Willi
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

#ifndef IKE_CFG_H_
#define IKE_CFG_H_

typedef struct ike_cfg_t ike_cfg_t;

#include <library.h>
#include <utils/host.h>
#include <utils/linked_list.h>
#include <utils/identification.h>
#include <config/proposal.h>
#include <crypto/diffie_hellman.h>

/**
 * @brief An ike_cfg_t defines the rules to set up an IKE_SA.
 *
 * @see peer_cfg_t to get an overview over the configurations.
 *
 * @b Constructors:
 *  - ike_cfg_create()
 *
 * @ingroup config
 */
struct ike_cfg_t {
	
	/**
	 * @brief Get own address.
	 * 
	 * @param this	calling object
	 * @return		host information as host_t object
	 */
	host_t* (*get_my_host) (ike_cfg_t *this);

	/**
	 * @brief Get peers address.
	 * 
	 * @param this	calling object
	 * @return		host information as host_t object
	 */
	host_t* (*get_other_host) (ike_cfg_t *this);
	
	/**
	 * @brief Adds a proposal to the list.
	 * 
	 * The first added proposal has the highest priority, the last
	 * added the lowest.
	 * 
	 * @param this		calling object
	 * @param proposal	proposal to add
	 */
	void (*add_proposal) (ike_cfg_t *this, proposal_t *proposal);
	
	/**
	 * @brief Returns a list of all supported proposals.
	 * 
	 * Returned list and its proposals must be destroyed after use.
	 * 
	 * @param this		calling object
	 * @return 			list containing all the proposals
	 */
	linked_list_t* (*get_proposals) (ike_cfg_t *this);
	
	/**
	 * @brief Select a proposed from suggested proposals.
	 * 
	 * Returned proposal must be destroyed after use.
	 * 
	 * @param this		calling object
	 * @param proposals	list of proposals to select from
	 * @return			selected proposal, or NULL if none matches.
	 */
	proposal_t *(*select_proposal) (ike_cfg_t *this, linked_list_t *proposals);
	
	/**
	 * @brief Should we send a certificate request in IKE_SA_INIT?
	 *
	 * @param this		calling object
	 * @return			certificate request sending policy
	 */
	bool (*send_certreq) (ike_cfg_t *this);
	
	/**
	 * @brief Get the DH group to use for IKE_SA setup.
	 * 
	 * @param this		calling object
	 * @return			dh group to use for initialization
	 */
	diffie_hellman_group_t (*get_dh_group)(ike_cfg_t *this);
	
	/**
	 * @brief Check if a suggested DH group is acceptable.
	 * 
	 * If we guess a wrong DH group for IKE_SA_INIT, the other
	 * peer will send us a offer. But is this acceptable for us?
	 * 
	 * @param this		calling object
	 * @return			TRUE if group acceptable
	 */
	bool (*check_dh_group) (ike_cfg_t *this, diffie_hellman_group_t dh_group);
	
	/**
	 * @brief Get a new reference to this ike_cfg.
	 *
	 * Get a new reference to this ike_cfg by increasing
	 * it's internal reference counter.
	 * Do not call get_ref or any other function until you
	 * already have a reference. Otherwise the object may get
	 * destroyed while calling get_ref(),
	 *
	 * @param this		calling object
	 */
	void (*get_ref) (ike_cfg_t *this);
	
	/**
	 * @brief Destroys a ike_cfg_t object.
	 * 
	 * Decrements the internal reference counter and
	 * destroys the ike_cfg when it reaches zero.
	 * 
	 * @param this		calling object
	 */
	void (*destroy) (ike_cfg_t *this);
};

/**
 * @brief Creates a ike_cfg_t object.
 *
 * Supplied hosts become owned by ike_cfg, the name gets cloned.
 *
 * @param name			ike_cfg identifier
 * @param certreq		TRUE to send a certificate request
 * @param my_host		host_t representing local address
 * @param other_host	host_t representing remote address
 * @return 				ike_cfg_t object.
 * 
 * @ingroup config
 */
ike_cfg_t *ike_cfg_create(bool certreq, host_t *my_host, host_t *other_host);

#endif /* IKE_CFG_H_ */
