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

/**
 * @brief Manages all configuration aspects of the daemon.
 * 
 */
typedef struct configuration_manager_s configuration_manager_t;

struct configuration_manager_s { 
	
	status_t (*get_remote_host) (configuration_manager_t *this, char *name, host_t **host);
	
	status_t (*get_local_host) (configuration_manager_t *this, char *name, host_t **host);
	
	status_t (*get_proposals_for_host) (configuration_manager_t *this, host_t *host, linked_list_iterator_t *list);
	
	status_t (*select_proposals_for_host)  (configuration_manager_t *this, host_t *host, linked_list_iterator_t *in, linked_list_iterator_t *out);

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
