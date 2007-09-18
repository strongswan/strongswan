/**
 * @file backend.h
 * 
 * @brief Interface backend_t.
 *  
 */

/*
 * Copyright (C) 2007 Martin Willi
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

#ifndef BACKEND_H_
#define BACKEND_H_

typedef struct backend_t backend_t;

#include <library.h>
#include <config/ike_cfg.h>
#include <config/peer_cfg.h>
#include <utils/linked_list.h>

/**
 * @brief The interface for a configuration backend.
 *
 * A configuration backend is loaded by the backend_manager. It does the actual
 * configuration lookup for the method it implements. See backend_manager_t for
 * more information.
 *
 * @b Constructors:
 * - implementations constructors
 * 
 * @ingroup backends
 */
struct backend_t {

	/**
	 * @brief Get an ike_cfg identified by two hosts.
	 *
	 * @param this				calling object
	 * @param my_host			address of own host
	 * @param other_host		address of remote host
	 * @return					matching ike_config, or NULL if none found
	 */
	ike_cfg_t *(*get_ike_cfg)(backend_t *this, 
							  host_t *my_host, host_t *other_host);
	
	/**
	 * @brief Get a peer_cfg identified by two IDs.
	 * 
	 * Select a config based on the two IDs and the other's certificate issuer
	 *
	 * @param this				calling object
	 * @param my_id				own ID
	 * @param other_id			peer ID
	 * @param other_ca_info		info record on issuer of peer certificate
	 * @return					matching peer_config, or NULL if none found
	 */
	peer_cfg_t *(*get_peer_cfg)(backend_t *this,
								identification_t *my_id, identification_t *other_id,
								ca_info_t *other_ca_info);
	
	/**
	 * @brief Get a peer_cfg identified by it's name, or a name of its child.
	 *
	 * @param this				calling object
	 * @param name				
	 * @return					matching peer_config, or NULL if none found
	 */
	peer_cfg_t *(*get_peer_cfg_by_name)(backend_t *this, char *name);
	
	/**
	 * @brief Check if a backend is writable and implements writable_backend_t.
	 *
	 * @param this		calling object
	 * @return			TRUE if backend implements writable_backend_t.
	 */
	bool (*is_writeable)(backend_t *this);
	
	/**
	 * @brief Destroy a backend.
	 *
	 * @param this		calling object
	 */
	void (*destroy)(backend_t *this);
};


/**
 * Construction to create a backend.
 */
typedef backend_t*(*backend_constructor_t)(void);

#endif /* BACKEND_H_ */

