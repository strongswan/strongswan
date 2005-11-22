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

#include "types.h"
#include "utils/linked_list.h"
#include "utils/host.h"
#include "payloads/transform_substructure.h"
#include "transforms/prfs/prf.h"
#include "transforms/signers/signer.h"
#include "transforms/crypters/crypter.h"

/**
 * @brief Manages all configuration aspects of the daemon.
 * 
 */
typedef struct configuration_manager_s configuration_manager_t;

struct configuration_manager_s { 
	
	/**
	 * Gets the remote host informations for a specific configuration name
	 * 
	 * @param this	calling object
	 * @param name	name of the configuration
	 * @param host	remote host informations are stored at this location
	 * 
	 * @return		
	 * 				- NOT_FOUND
	 * 				- SUCCESS
	 * 				- OUT_OF_RES
	 */
	status_t (*get_remote_host) (configuration_manager_t *this, char *name, host_t **host);
	
	status_t (*get_local_host) (configuration_manager_t *this, char *name, host_t **host);
	
	status_t (*get_dh_group_number) (configuration_manager_t *this, char *name, u_int16_t *dh_group_number, u_int16_t priority);
	
	status_t (*get_proposals_for_host) (configuration_manager_t *this, host_t *host, linked_list_iterator_t *list);
	
	status_t (*select_proposals_for_host) (configuration_manager_t *this, host_t *host, linked_list_iterator_t *in, linked_list_iterator_t *out);
	
	status_t (*get_transforms_for_host_and_proposals) (configuration_manager_t *this, host_t *host, linked_list_iterator_t *proposals,crypter_t **crypter,signer_t **signer, prf_t **prf);
	
	status_t (*is_dh_group_allowed_for_host) (configuration_manager_t *this, host_t *host, diffie_hellman_group_t group, bool *allowed);
	
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
