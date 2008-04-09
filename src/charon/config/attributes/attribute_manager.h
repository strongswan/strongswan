/*
 * Copyright (C) 2008 Martin Willi
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
 *
 * $Id$
 */

/**
 * @defgroup attribute_manager attribute_manager
 * @{ @ingroup attributes
 */

#ifndef ATTRIBUTE_MANAGER_H_
#define ATTRIBUTE_MANAGER_H_

#include <config/attributes/attribute_provider.h>

typedef struct attribute_manager_t attribute_manager_t;

/**
 * Provide configuration attributes to include in CFG Payloads.
 */
struct attribute_manager_t {

	/**
	 * Acquire a virtual IP address to assign to a peer.
	 *
	 * @param pool			pool name to acquire address from
	 * @param id			peer identity to get address for
	 * @param auth			authorization infos of peer
	 * @param requested		IP in configuration request
	 * @return				allocated address, NULL to serve none
	 */
	host_t* (*acquire_address)(attribute_manager_t *this,
							   char *pool, identification_t *id,
							   auth_info_t *auth, host_t *requested);
	
	/**
	 * Release a previously acquired address.
	 *
	 * @param pool			pool name from which the address was acquired
	 * @param address		address to release
	 */
	void (*release_address)(attribute_manager_t *this,
							char *pool, host_t *address);
	
	/**
	 * Register an attribute provider to the manager.
	 *
	 * @param provider		attribute provider to register
	 */
	void (*add_provider)(attribute_manager_t *this,
						 attribute_provider_t *provider);
	/**
	 * Unregister an attribute provider from the manager.
	 *
	 * @param provider		attribute provider to unregister
	 */
	void (*remove_provider)(attribute_manager_t *this,
							attribute_provider_t *provider);
	/**
     * Destroy a attribute_manager instance.
     */
    void (*destroy)(attribute_manager_t *this);
};

/**
 * Create a attribute_manager instance.
 */
attribute_manager_t *attribute_manager_create();

#endif /* ATTRIBUTE_MANAGER_H_ @}*/
