/**
 * @file backend_manager.h
 * 
 * @brief Interface backend_manager_t.
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

#ifndef BACKEND_MANAGER_H_
#define BACKEND_MANAGER_H_

typedef struct backend_manager_t backend_manager_t;

#include <library.h>
#include <utils/host.h>
#include <utils/identification.h>
#include <config/ike_cfg.h>
#include <config/peer_cfg.h>
#include <config/backends/backend.h>


/**
 * @brief A loader and multiplexer to use multiple backends.
 *
 * Charon allows the use of multiple configuration backends simultaneously. To
 * access all this backends by a single call, this class wraps multiple
 * backends behind a single object. It is also responsible for loading
 * the backend modules and cleaning them up.
 * A backend may be writeable or not. All backends implement the backend_t
 * interface, those who are writeable additionally implement the
 * writeable_backend_t interface. Adding configs to the backend_manager will
 * be redirected to the first writeable backend.
 * @verbatim

   +---------+      +-----------+         +--------------+     |
   |         |      |           |       +--------------+ |     |
   | daemon  |----->| backend_- |     +--------------+ |-+  <==|==> IPC
   |  core   |      | manager   |---->|   backends   |-+       |
   |         |----->|           |     +--------------+         |
   |         |      |           |                              |
   +---------+      +-----------+                              |
   
   @endverbatim
 *
 * @b Constructors:
 * - backend_manager_create()
 * 
 * @ingroup config
 */
struct backend_manager_t {
	
	/**
	 * @brief Get an ike_config identified by two hosts.
	 *
	 * @param this				calling object
	 * @param my_host			address of own host
	 * @param other_host		address of remote host
	 * @return					matching ike_config, or NULL if none found
	 */
	ike_cfg_t *(*get_ike_cfg)(backend_manager_t *this, 
							  host_t *my_host, host_t *other_host);
	
	/**
	 * @brief Get a peer_config identified by two IDs.
	 *
	 * @param this				calling object
	 * @param my_id				own ID
	 * @param other_id			peers ID
	 * @return					matching peer_config, or NULL if none found
	 */
	peer_cfg_t *(*get_peer_cfg)(backend_manager_t *this, identification_t *my_id,
								identification_t *other_id);
	
	/**
	 * @brief Add a peer_config to the first found writable backend.
	 *
	 * @param this		calling object
	 * @param config	peer_config to add to the backend
	 */
	void (*add_peer_cfg)(backend_manager_t *this, peer_cfg_t *config);
	
	/**
	 * @brief Create an iterator over all peer configs of the writable backend.
	 *
	 * @param this		calling object
	 * @return 			iterator over peer configs
	 */
	iterator_t* (*create_iterator)(backend_manager_t *this);
	
	/**
	 * @brief Destroys a backend_manager_t object.
	 *
	 * @param this 					calling object
	 */
	void (*destroy) (backend_manager_t *this);
};

/**
 * @brief Creates a new instance of the manager and loads all backends.
 *
 * @return		backend_manager instance
 *
 * @ingroup config
 */
backend_manager_t *backend_manager_create(void);

#endif /*BACKEND_MANAGER_H_*/

