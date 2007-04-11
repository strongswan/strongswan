/**
 * @file cfg_store.h
 * 
 * @brief Interface cfg_store_t.
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

#ifndef CFG_STORE_H_
#define CFG_STORE_H_

typedef struct cfg_store_t cfg_store_t;

#include <library.h>
#include <utils/host.h>
#include <utils/identification.h>
#include <config/ike_cfg.h>
#include <config/peer_cfg.h>
#include <config/backends/backend.h>


/**
 * @brief A multiplexer to use multiple cfg_store backends.
 *
 * Charon allows the use of multiple cfg_store backends simultaneously. To
 * access all this backends by a single call, this class wraps multiple
 * backends behind a single object.
 * Backends may be registered and unregister at runtime dynamically.
 * @verbatim

   +---------+      +-----------+         +--------------+     |
   |         |      |           |       +--------------+ |     |
   | daemon  |----->| cfg_store |     +--------------+ |-+  <==|==> IPC
   |  core   |      |           |---->|   backends   |-+       |
   |         |----->|           |     +--------------+         |
   |         |      |           |                              |
   +---------+      +-----------+                              |
   
   @endverbatim
 * Configuration lookup is done only when acting as responder. For initating
 * the corresponding controller is responsible to get a config to initiate.
 *
 * @b Constructors:
 * - cfg_store_create()
 * 
 * @ingroup config
 */
struct cfg_store_t {
	
	/**
	 * @brief Get an ike_config identified by two hosts.
	 *
	 * @param this				calling object
	 * @param my_host			address of own host
	 * @param other_host		address of remote host
	 * @return					matching ike_config, or NULL if none found
	 */
	ike_cfg_t *(*get_ike_cfg)(cfg_store_t *this, 
							  host_t *my_host, host_t *other_host);
	
	/**
	 * @brief Get a peer_config identified by two IDs.
	 *
	 * @param this				calling object
	 * @param my_id				own ID
	 * @param other_id			peers ID
	 * @return					matching peer_config, or NULL if none found
	 */
	peer_cfg_t *(*get_peer_cfg)(cfg_store_t *this, identification_t *my_id,
								identification_t *other_id);
	
	/**
	 * @brief Register a backend to be queried by the calls above.
	 *
	 * The backend first added is the most preferred.
	 *
	 * @param this 					calling object
	 */
	void (*register_backend) (cfg_store_t *this, backend_t *backend);
	
	/**
	 * @brief Unregister a backend.
	 *
	 * @param this 					calling object
	 */
	void (*unregister_backend) (cfg_store_t *this, backend_t *backend);
	
	/**
	 * @brief Destroys a cfg_store_t object.
	 *
	 * @param this 					calling object
	 */
	void (*destroy) (cfg_store_t *this);
};

/**
 * @brief Create a new instance of the store.
 *
 * @return		cfg_store instance
 *
 * @ingroup config
 */
cfg_store_t *cfg_store_create(void);

#endif /*CFG_STORE_H_*/
