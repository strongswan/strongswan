/**
 * @file local_backend.h
 *
 * @brief Interface of local_backend_t.
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
 
#ifndef LOCAL_BACKEND_H_
#define LOCAL_BACKEND_H_

typedef struct local_backend_t local_backend_t;

#include <library.h>
#include <config/backends/backend.h>

/**
 * @brief An in-memory backend to store configuration information.
 *
 * The local_backend_t stores the configuration in a simple list. Additional
 * to the backend_t functionality, it adds the modification (add/remove).
 *
 * @b Constructors:
 *  - local_backend_create()
 * 
 * @ingroup backends
 */
struct local_backend_t {
	
	/**
	 * Implements backend_t interface
	 */
	backend_t backend;
	
	/**
	 * @brief Add a peer_config to the backend.
	 *
	 * @param this		calling object
	 * @param config	peer_config to add to the backend
	 */
	void (*add_peer_cfg)(local_backend_t *this, peer_cfg_t *config);
	
	/**
	 * @brief Get a peer_config identified by name, or a name of its child_cfgs.
	 *
	 * @param this				calling object
	 * @param name				name of the peer config
	 * @return					matching peer_config, or NULL if none found
	 */
	peer_cfg_t *(*get_peer_cfg_by_name)(local_backend_t *this, char *name);
	
	/**
	 * @brief Create an iterator over all peer configs.
	 *
	 * @param this		calling object
	 * @return 			iterator over peer configs
	 */
	iterator_t* (*create_peer_cfg_iterator)(local_backend_t *this);
	
	/**
	 * @brief Destroy a local backend.
	 *
	 * @param this		calling object
	 */
	void (*destroy)(local_backend_t *this);
};

/**
 * @brief Creates a local_backend_t instance.
 *
 * @return local_backend instance.
 * 
 * @ingroup config
 */
local_backend_t *local_backend_create(void);

#endif /* LOCAL_BACKEND_H_ */
