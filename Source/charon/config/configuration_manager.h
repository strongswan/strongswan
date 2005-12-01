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
#include <config/init_config.h>
#include <config/sa_config.h>


typedef struct configuration_manager_t configuration_manager_t;

/**
 * @brief Manages all configuration aspects of the daemon.
 * 
 * @ingroup config
 * 
 */
struct configuration_manager_t { 

	/**
	 * Gets the configuration information needed for IKE_SA_INIT exchange 
	 * for a specific configuration name.
	 * 
	 * The returned init_config_t object MUST NOT be destroyed cause it's the original one.
	 * 
	 * @param this				calling object
	 * @param name				name of the configuration
	 * @param[out] init_config	the configuration is stored at this place
	 * 
	 * @return		
	 * 				- NOT_FOUND
	 * 				- SUCCESS
	 */
	status_t (*get_init_config_for_name) (configuration_manager_t *this, char *name, init_config_t **init_config);

	/**
	 * Gets the configuration information needed for IKE_SA_INIT exchange 
	 * for specific host informations.
	 * 
	 * The returned init_config_t object MUST NOT be destroyed cause it's the original one.
	 * 
	 * @param this				calling object
	 * @param my_host			my host informations
	 * @param other_host			other host informations
	 * @param[out] init_config	the configuration is stored at this place
	 * 
	 * @return		
	 * 				- NOT_FOUND
	 * 				- SUCCESS
	 */	
	status_t (*get_init_config_for_host) (configuration_manager_t *this, host_t *my_host, host_t *other_host,init_config_t **init_config);
	
	/**
	 * Gets the configuration information needed after IKE_SA_INIT exchange.
	 * 
	 * The returned sa_config_t object MUST not be destroyed cause it's the original one.
	 * 
	 * @param this				calling object
	 * @param name				name of the configuration
	 * @param[out] sa_config	the configuration is stored at this place
	 * 
	 * @return		
	 * 				- NOT_FOUND
	 * 				- SUCCESS
	 */
	status_t (*get_sa_config_for_name) (configuration_manager_t *this, char *name, sa_config_t **sa_config);
	
	/**
	 * Gets the configuration information needed after IKE_SA_INIT exchange 
	 * for specific init_config_t and ID data.
	 * 
	 * The returned sa_config_t object MUST NOT be destroyed cause it's the original one.
	 * 
	 * @param this				calling object
	 * @param init_config		init_config_t object
	 * @param other_id			identification of other one
	 * @param my_id			my identification (can be NULL)
	 * @param[out] sa_config	the configuration is stored at this place
	 * 
	 * @return		
	 * 				- NOT_FOUND
	 * 				- SUCCESS
	 */	
	status_t (*get_sa_config_for_init_config_and_id) (configuration_manager_t *this, init_config_t *init_config, identification_t *other_id, identification_t *my_id,sa_config_t **sa_config);

	/**
	 * Destroys configuration manager
	 * 
	 * 
	 * @param this				calling object
	 * @return		
	 * 							- SUCCESS
	 */
	void (*destroy) (configuration_manager_t *this);
};

/**
 * Creates the mighty configuration manager
 * 
 * @return 
 * 			- pointer to created manager object if succeeded
 * 			- NULL if memory allocation failed
 * 
 * @ingroup config
 */
configuration_manager_t *configuration_manager_create();

#endif /*CONFIGURATION_MANAGER_H_*/
