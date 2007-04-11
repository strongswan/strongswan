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
 * A configuration backend is registered in the cfg_store. It does the actual
 * configuration lookup for the method it implements. See cfg_store_t for
 * more information.
 *
 * @b Constructors:
 * - none, use implementations of backend_t.
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
	 * @param this				calling object
	 * @param my_id				own ID
	 * @param other_id			peers ID
	 * @return					matching peer_config, or NULL if none found
	 */
	peer_cfg_t *(*get_peer_cfg)(backend_t *this,
								   identification_t *my_id,
								   identification_t *other_id);
	
	/**
	 * @brief Get a peer_cfg identified by its name.
	 *
	 * @param this				calling object
	 * @param name				configs name
	 * @return					matching peer_config, or NULL if none found
	 */
	peer_cfg_t *(*get_peer_cfg_by_name)(backend_t *this, char *name);
};

#endif /* BACKEND_H_ */
