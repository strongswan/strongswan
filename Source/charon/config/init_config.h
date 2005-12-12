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
#include <utils/iterator.h>
#include <transforms/crypters/crypter.h>
#include <transforms/prfs/prf.h>
#include <transforms/signers/signer.h>
#include <transforms/diffie_hellman.h>


typedef struct ike_proposal_t ike_proposal_t;

/**
 * @brief Represents a Proposal used in IKE_SA_INIT phase.
 * 
 * @todo Currently the amount of tranforms with same type in a IKE proposal is limited to 1.
 * 		 Support of more transforms with same type has to be added.
 * 
 * @ingroup config
 */
struct ike_proposal_t {
	/**
	 * Encryption algorithm.
	 */
	encryption_algorithm_t encryption_algorithm;
	
	/**
	 * Key length of encryption algorithm in bytes.
	 */
	u_int16_t encryption_algorithm_key_length;
	
	/**
	 * Integrity algorithm.
	 */
	integrity_algorithm_t integrity_algorithm;
	
	/**
	 * Key length of integrity algorithm.
	 */
	u_int16_t integrity_algorithm_key_length;
	
	/**
	 * Pseudo random function (prf).
	 */
	pseudo_random_function_t pseudo_random_function;
	
	/**
	 * Key length of prf.
	 */
	u_int16_t pseudo_random_function_key_length;
	
	/**
	 * Diffie hellman group.
	 */
	diffie_hellman_group_t diffie_hellman_group;
};


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
	host_t * (*get_my_host) (init_config_t *this);

	/**
	 * @brief Get other host information as host_t object.
	 * 
	 * Object is NOT getting cloned.
	 * 
	 * @param this	calling object
	 * @return		host information as host_t object
	 */
	host_t * (*get_other_host) (init_config_t *this);
	
	/**
	 * @brief Get my host information as host_t object.
	 * 
	 * Object is getting cloned and has to get destroyed by caller.
	 * 
	 * @param this	calling object
	 * @return		host information as host_t object
	 */
	host_t * (*get_my_host_clone) (init_config_t *this);

	/**
	 * @brief Get other host information as host_t object.
	 * 
	 * @warning Object is getting cloned and has to get destroyed by caller.
	 * 
	 * @param this	calling object
	 * @return		host information as host_t object
	 */
	host_t * (*get_other_host_clone) (init_config_t *this);
	
	/**
	 * @brief Get the diffie hellman group to use as initiator with given priority.
	 * 
	 * @param this		calling object
	 * @param priority 	priority of dh group number (starting at 1)
	 * @return			diffie hellman group number for given priority or 
	 * 					MODP_UNDEFINED for not supported priorities
	 */
	diffie_hellman_group_t (*get_dh_group_number) (init_config_t *this,size_t priority);
	
	/**
	 * @brief Returns a list of all supported ike_proposals of type ike_proposal_t *.
	 * 
	 * Returned array of ike_proposal_t has to get destroyed by the caller.
	 * 
	 * @param this				calling object
	 * @param proposals			first proposal in a array
	 * @return 					number of proposals in array
	 */
	size_t (*get_proposals) (init_config_t *this,ike_proposal_t **proposals);
	
	/**
	 * @brief Adds a proposal with given priority to the current stored proposals.
	 * 
	 * If allready a proposal with given priority is stored the other one is 
	 * moved one priority back. If priority is higher then all other stored 
	 * proposals, it is inserted as last one.
	 * 
	 * @param this				calling object
	 * @param priority			priority of adding proposal
	 * @param proposal			proposal to add
	 */
	void (*add_proposal) (init_config_t *this,size_t priority, ike_proposal_t proposal);
	
	/**
	 * @brief Select a proposed from suggested proposals.
	 * 
	 * @param this					calling object
	 * @param suggested_proposals	first proposal in a array
	 * @param proposal_count		number of suggested proposals in array
	 * @param selected_proposal		the ike_proposal_t pointing to is set
	 * @return						
	 * 								- SUCCESS if a proposal was selected
	 * 								- NOT_FOUND if none of suggested proposals is supported
	 */
	status_t (*select_proposal) (init_config_t *this, ike_proposal_t *proposals, size_t proposal_count, ike_proposal_t *selected_proposal);
	
	/**
	 * @brief Destroys a init_config_t object.
	 * 
	 * @param this	calling object
	 */
	void (*destroy) (init_config_t *this);
};

/**
 * @brief Creates a init_config_t object.
 * 
 * @return init_config_t object.
 * 
 * @ingroup config
 */
init_config_t * init_config_create(char * my_ip, char *other_ip, u_int16_t my_port, u_int16_t other_port);

#endif //_INIT_CONFIG_H_
