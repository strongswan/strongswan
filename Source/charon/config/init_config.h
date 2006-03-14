/**
 * @file init_config.h
 * 
 * @brief Interface of init_config_t.
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
 
#ifndef _INIT_CONFIG_H_
#define _INIT_CONFIG_H_

#include <types.h>
#include <network/host.h>
#include <utils/linked_list.h>
#include <config/proposal.h>
#include <transforms/crypters/crypter.h>
#include <transforms/prfs/prf.h>
#include <transforms/signers/signer.h>
#include <transforms/diffie_hellman.h>



typedef struct init_config_t init_config_t;

/**
 * @brief Represents a configuration class holding all needed informations for IKE_SA_INIT phase.
 * 
 * @b Constructors:
 *  - init_config_create()
 * 
 * @ingroup config
 */
struct init_config_t { 

	/**
	 * @brief Get my host information as host_t object.
	 * 
	 * Object is NOT getting cloned.
	 * 
	 * @param this	calling object
	 * @return		host information as host_t object
	 */
	host_t *(*get_my_host) (init_config_t *this);

	/**
	 * @brief Get other host information as host_t object.
	 * 
	 * Object is NOT getting cloned.
	 * 
	 * @param this	calling object
	 * @return		host information as host_t object
	 */
	host_t *(*get_other_host) (init_config_t *this);
	
	/**
	 * @brief Get my host information as host_t object.
	 * 
	 * Object is getting cloned and has to get destroyed by caller.
	 * 
	 * @param this	calling object
	 * @return		host information as host_t object
	 */
	host_t *(*get_my_host_clone) (init_config_t *this);

	/**
	 * @brief Get other host information as host_t object.
	 * 
	 * @warning Object is getting cloned and has to get destroyed by caller.
	 * 
	 * @param this	calling object
	 * @return		host information as host_t object
	 */
	host_t *(*get_other_host_clone) (init_config_t *this);
	
	/**
	 * @brief Returns a list of all supported proposals.
	 * 
	 * Returned list is still owned by init_config and MUST NOT
	 * modified or destroyed.
	 * 
	 * @param this				calling object
	 * @return 					list containing all the proposals
	 */
	linked_list_t *(*get_proposals) (init_config_t *this);
	
	/**
	 * @brief Adds a proposal to the list..
	 * 
	 * The first added proposal has the highest priority, the last
	 * added the lowest.
	 * 
	 * @param this				calling object
	 * @param priority			priority of adding proposal
	 * @param proposal			proposal to add
	 */
	void (*add_proposal) (init_config_t *this, proposal_t *proposal);
	
	/**
	 * @brief Select a proposed from suggested proposals.
	 * 
	 * Returned proposal must be destroyed after usage.
	 * 
	 * @param this					calling object
	 * @param proposals				list of proposals to select from
	 * @return						selected proposal, or NULL if none matches.
	 */
	proposal_t *(*select_proposal) (init_config_t *this, linked_list_t *proposals);
	
	/**
	 * @brief Get the DH group to use for connection initialization.
	 * 
	 * @param this					calling object
	 * @return						dh group to use for initialization
	 */
	diffie_hellman_group_t (*get_dh_group) (init_config_t *this);
	
	/**
	 * @brief Check if a suggested dh group is acceptable.
	 * 
	 * If we guess a wrong DH group for IKE_SA_INIT, the other
	 * peer will send us a offer. But is this acceptable for us?
	 * 
	 * @param this					calling object
	 * @return						dh group to use for initialization
	 */
	bool (*check_dh_group) (init_config_t *this, diffie_hellman_group_t dh_group);
	
	/**
	 * @brief Destroys a init_config_t object.
	 * 
	 * @param this	calling object
	 */
	void (*destroy) (init_config_t *this);
};

/**
 * @brief Creates a init_config_t object from two host_t's.
 * 
 * Supplied hosts become owned by init_config, so 
 * do not modify or destroy them after a call to 
 * init_config_create_from_hosts().
 * 
 * @param me		host_t object representing local address
 * @param other		host_t object representing remote address
 * @return init_config_t object.
 * 
 * @ingroup config
 */
init_config_t * init_config_create(host_t *me, host_t *other);

#endif /* _INIT_CONFIG_H_ */
