/**
 * @file writeable_backend.h
 *
 * @brief Interface of writeable_backend_t.
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
 
#ifndef WRITEABLE_BACKEND_H_
#define WRITEABLE_BACKEND_H_

typedef struct writeable_backend_t writeable_backend_t;

#include <library.h>
#include <config/backends/backend.h>

/**
 * @brief A writeable backend extends backend_t by modification functions.
 *
 * @b Constructors:
 *  - writeable_backend_create()
 * 
 * @ingroup backends
 */
struct writeable_backend_t {
	
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
	void (*add_cfg)(writeable_backend_t *this, peer_cfg_t *config);
	
	/**
	 * @brief Create an iterator over all peer configs.
	 *
	 * @param this		calling object
	 * @return 			iterator over peer configs
	 */
	iterator_t* (*create_iterator)(writeable_backend_t *this);
};

#endif /* WRITEABLE_BACKEND_H_ */

