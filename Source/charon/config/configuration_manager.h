/**
 * @file configuration_manager.h
 * 
 * @brief Manages all configuration aspects of the daemon.
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

#ifndef CONFIGURATION_MANAGER_H_
#define CONFIGURATION_MANAGER_H_

#include <types.h>
#include <utils/linked_list.h>
#include <network/host.h>
#include <encoding/payloads/transform_substructure.h>
#include <transforms/prfs/prf.h>
#include <transforms/signers/signer.h>
#include <transforms/crypters/crypter.h>

/**
 * @brief Manages all configuration aspects of the daemon.
 * 
 * Currently the configuration manager class does not store specific configurations.
 * It is expected, that in future different configurations are stored in a linked list 
 * or a hash map and are managed by this class.
 * 
 */
typedef struct configuration_manager_s configuration_manager_t;

struct configuration_manager_s { 
	
	/**
	 * Gets the remote host information for a specific configuration name.
	 * 
	 * A host information consist of IP address and UDP port.
	 * 
	 * @param this	calling object
	 * @param name	name of the configuration
	 * @param host	remote host information gets stored at this location
	 * 
	 * @return		
	 * 				- OUT_OF_RES
	 * 				- NOT_FOUND
	 * 				- SUCCESS
	 */
	status_t (*get_remote_host) (configuration_manager_t *this, char *name, host_t **host);

	/**
	 * Gets the local host information for a specific configuration name
	 * 
	 * A host information consist of IP address and UDP port.
	 * 
	 * @param this	calling object
	 * @param name	name of the configuration
	 * @param host	local host information gets stored at this location
	 * 
	 * @return		
	 * 				- OUT_OF_RES
	 * 				- NOT_FOUND (not yet implemented)
	 * 				- SUCCESS
	 */
	status_t (*get_local_host) (configuration_manager_t *this, char *name, host_t **host);
	
	/**
	 * Returns the DH group number to use when initiating a connection.
	 * 
	 * To make sure that different group numbers are supported in case 
	 * a group number is not supported by other peer, a priority has to get defined.
	 * 
	 * 
	 * @param this				calling object
	 * @param name				name of the configuration
	 * @param dh_group_number	the DH group number gets stored at this location
	 * @param priority			priority to use for selection of DH group number.
	 * 							Highest priority is 1. All higher values have lower
	 * 							priority.
	 * 
	 * @return		
	 *							- FAILED (not yet implemented)
	 * 							- NOT_FOUND (not yet implemented)
	 * 							- SUCCESS
	 */
	status_t (*get_dh_group_number) (configuration_manager_t *this, char *name, u_int16_t *dh_group_number, u_int16_t priority);
	
	/**
	 * Returns the proposals which should be used to initiate a connection with a specific
	 * host.
	 * 
	 * The proposals of type proposal_substructure_t * are returned over the given iterator 
	 * and have to be destroyed by the caller.
	 * 
	 * 
	 * @param this				calling object
	 * @param host				host information used to find the correct proposals
	 * @param list				iterator where the proposals are written to
	 * 
	 * @return		
	 * 							- OUT_OF_RES
	 * 							- NOT_FOUND (not yet implemented)
	 * 							- SUCCESS
	 */
	status_t (*get_proposals_for_host) (configuration_manager_t *this, host_t *host, linked_list_iterator_t *list);
	
	/**
	 * Checks the suggested proposals passed as iterator in and selects one proposal to be sent as selection
	 * of this proposals.
	 * 
	 * Currently there is no check implemented. The first suggested proposal is cloned and then as selected returned.
	 * 
	 * 
	 * @param this				calling object
	 * @param host				host information used to find the correct proposals
	 * @param in					iterator with suggested proposals of type proposal_substructure_t *
	 * @param out				The selected proposals of type proposal_substructure_t * are written to this iterator
	 * 
	 * @return		
	 * 							- OUT_OF_RES
	 * 							- FAILED
	 * 							- NOT_FOUND (not yet implemented)
	 * 							- SUCCESS
	 */
	status_t (*select_proposals_for_host) (configuration_manager_t *this, host_t *host, linked_list_iterator_t *in, linked_list_iterator_t *out);
	
	/**
	 * Returns the transforms of type crypter_t, signer_t and prf_t as specified in given proposal.
	 * 
	 * 
	 * @param this							calling object
	 * @param host							host information
	 * @param proposals						iterator with selected proposals
	 * @param[out] encryption_algorithm		
	 * @param[out] pseudo_random_function	
	 * @param[out] integrity_algorithm		
	 * 
	 * @return		
	 * 										- OUT_OF_RES
	 * 										- FAILED
	 * 										- NOT_FOUND (not yet implemented)
	 * 										- SUCCESS
	 */
	status_t (*get_transforms_for_host_and_proposals) (configuration_manager_t *this, host_t *host, linked_list_iterator_t *proposals,encryption_algorithm_t *encryption_algorithm,pseudo_random_function_t *pseudo_random_function, integrity_algorithm_t *integrity_algorithm);
	
	/**
	 * Checks if a given dh_group number is allowed for a specific host
	 * 
	 * 
	 * @param this				calling object
	 * @param host				host information
	 * @param group				DH group number to check if allowed
	 * @param[out] allowed		will be set to TRUE if group number is allowed, FALSE otherwise
	 * 
	 * @return		
	 * 							- FAILED
	 * 							- NOT_FOUND (not yet implemented)
	 * 							- SUCCESS
	 */
	status_t (*is_dh_group_allowed_for_host) (configuration_manager_t *this, host_t *host, diffie_hellman_group_t group, bool *allowed);
	
	/**
	 * Destroys configuration manager
	 * 
	 * 
	 * @param this				calling object
	 * @return		
	 * 							- SUCCESS
	 */
	status_t (*destroy) (configuration_manager_t *this);
};

/**
 * Creates the mighty configuration manager
 * 
 * @return 
 * 			- pointer to created manager object if succeeded
 * 			- NULL if memory allocation failed
 */
configuration_manager_t *configuration_manager_create();

#endif /*CONFIGURATION_MANAGER_H_*/
