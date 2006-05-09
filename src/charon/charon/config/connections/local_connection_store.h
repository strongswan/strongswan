/**
 * @file local_connection_store.h
 * 
 * @brief Interface of local_connection_store_t.
 *  
 */

/*
 * Copyright (C) 2006 Martin Willi
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
 
#ifndef LOCAL_CONNECTION_H_
#define LOCAL_CONNECTION_H_

#include <types.h>
#include <config/connections/connection_store.h>


typedef struct local_connection_store_t local_connection_store_t;

/**
 * @brief A connection_store_t implementation using a simple connection list.
 *
 * The local_connection_store_t class implements the connection_store_t interface
 * as simple as possible. connection_t's are stored in an in-memory list.
 *
 * @b Constructors:
 *  - local_connection_store_create()
 *
 * @todo Make thread-save first
 * @todo Add remove_connection method
 *
 * @ingroup config
 */
struct local_connection_store_t {
	
	/**
	 * Implements connection_store_t interface
	 */
	connection_store_t connection_store;
};

/**
 * @brief Creates a local_connection_store_t instance.
 *
 * @return connection store instance.
 * 
 * @ingroup config
 */
local_connection_store_t * local_connection_store_create(void);

#endif /* LOCAL_CONNECTION_H_ */
