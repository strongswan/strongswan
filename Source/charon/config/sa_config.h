/**
 * @file sa_config.h
 * 
 * @brief Interface of sa_config_t.
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

#ifndef _SA_CONFIG_H_
#define _SA_CONFIG_H_

#include <types.h>
#include <utils/identification.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/transform_substructure.h>
#include <network/host.h>
#include <transforms/crypters/crypter.h>
#include <transforms/signers/signer.h>
#include <transforms/diffie_hellman.h>
#include <config/traffic_selector.h>
#include <config/proposal.h>



typedef struct sa_config_t sa_config_t;

/**
 * @brief Stores configuration of an initialized connection.
 * 
 * During the IKE_AUTH phase, we have enough data to specify a 
 * configuration. 
 * 
 * @warning This config is not thread save.
 * 
 * @b Constructors:
 *   - sa_config_create()
 * 
 * @ingroup config
 */
struct sa_config_t {
	
	/**
	 * @brief Get own id to use for identification.
	 * 
	 * Returned object is not getting cloned.
	 * 
	 * @param this			calling object
	 * @return				own id
	 */
	identification_t *(*get_my_id) (sa_config_t *this);
	
	/**
	 * @brief Get id of communication partner.
	 *
	 * Returned object is not getting cloned.
	 * 
	 * @param this			calling object
	 * @return				other id
	 */
	identification_t *(*get_other_id) (sa_config_t *this);
	
	/**
	 * @brief Get authentication method to use for IKE_AUTH.
	 * 
	 * @param this			calling object
	 * @return				authentication methood
	 */
	auth_method_t (*get_auth_method) (sa_config_t *this);
	
	/**
	 * @brief Get lifetime of IKE_SA in milliseconds.
	 * 
	 * @return 				IKE_SA lifetime in milliseconds.
	 */
	u_int32_t (*get_ike_sa_lifetime) (sa_config_t *this);
	
	/**
	 * @brief Get configured traffic selectors for our site.
	 * 
	 * Returns a list with all traffic selectors for the local
	 * site. List and items MUST NOT be freed nor modified.
	 * 
	 * @param this						calling object
	 * @return							list with traffic selectors
	 */
	linked_list_t *(*get_my_traffic_selectors) (sa_config_t *this);
	
	/**
	 * @brief Get configured traffic selectors for others site.
	 * 
	 * Returns a list with all traffic selectors for the remote
	 * site. List and items MUST NOT be freed nor modified.
	 * 
	 * @param this						calling object
	 * @return							list with traffic selectors
	 */
	linked_list_t *(*get_other_traffic_selectors) (sa_config_t *this);
	
	/**
	 * @brief Select traffic selectors from a supplied list for local site.
	 * 
	 * Resulted list and traffic selectors must be destroyed after usage.
	 * 
	 * @param this						calling object
	 * @param supplied					linked list with traffic selectors
	 * @return							list containing the selected traffic selectors
	 */
	linked_list_t *(*select_my_traffic_selectors) (sa_config_t *this, linked_list_t *supplied);
		
	/**
	 * @brief Select traffic selectors from a supplied list for remote site.
	 * 
	 * Resulted list and traffic selectors must be destroyed after usage.
	 * 
	 * @param this						calling object
	 * @param supplied					linked list with traffic selectors
	 * @return							list containing the selected traffic selectors
	 */
	linked_list_t *(*select_other_traffic_selectors) (sa_config_t *this, linked_list_t *supplied);
	
	/**
	 * @brief Get the list of internally stored proposals.
	 * 
	 * Rembember: sa_config_t does store proposals for AH/ESP, 
	 * IKE proposals are in the init_config_t
	 * 
	 * @warning List and Items are still owned by sa_config and MUST NOT
	 *			be manipulated or freed!
	 * 
	 * @param this					calling object
	 * @return						lists with proposals
	 */
	linked_list_t *(*get_proposals) (sa_config_t *this);
	
	/**
	 * @brief Select a proposal from a supplied list.
	 * 
	 * @param this					calling object
	 * @param proposals				list from from wich proposals are selected
	 * @return						selected proposal, or NULL if nothing matches
	 */
	proposal_t *(*select_proposal) (sa_config_t *this, linked_list_t *proposals);
	
	/**
	 * @brief Add a traffic selector to the list for local site.
	 * 
	 * After add, proposal is owned by sa_config.
	 * 
	 * @warning Do not add while other threads are reading.
	 * 
	 * @param this					calling object
	 * @param traffic_selector		traffic_selector to add
	 */
	void (*add_my_traffic_selector) (sa_config_t *this, traffic_selector_t *traffic_selector);
	
	/**
	 * @brief Add a traffic selector to the list for remote site.
	 * 
	 * After add, proposal is owned by sa_config.
	 * 
	 * @warning Do not add while other threads are reading.
	 * 
	 * @param this					calling object
	 * @param traffic_selector		traffic_selector to add
	 */
	void (*add_other_traffic_selector) (sa_config_t *this, traffic_selector_t *traffic_selector);
	
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
	void (*add_proposal) (sa_config_t *this, proposal_t *proposal);
	
	/**
	 * @brief Destroys the config object
	 * 
	 * @param this				calling object
	 */
	void (*destroy) (sa_config_t *this);
};

/**
 * @brief Create a configuration object for IKE_AUTH and later.
 * 
 * @param my_id_type		type of my identification
 * @param my_id 			my identification as string
 * @param other_id_type		type of other identification
 * @param other_id 			other identification as string
 * @param auth_method		Method of authentication
 * @param ike_sa_lifetime	lifetime of this IKE_SA in milliseconds. IKE_SA will be deleted
 * 							after this lifetime!
 * @return 					sa_config_t object
 * 
 * @ingroup config
 */
sa_config_t *sa_config_create(id_type_t my_id_type, char *my_id, id_type_t other_id_type, char *other_id, auth_method_t auth_method, u_int32_t ike_sa_lifetime);

#endif //_SA_CONFIG_H_
