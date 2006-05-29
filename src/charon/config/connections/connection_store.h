/**
 * @file connection_store.h
 *
 * @brief Interface connection_store_t.
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

#ifndef CONNECTION_STORE_H_
#define CONNECTION_STORE_H_

#include <types.h>
#include <config/connections/connection.h>
#include <utils/logger.h>


typedef struct connection_store_t connection_store_t;

/**
 * @brief The interface for a store of connection_t's.
 * 
 * @b Constructors:
 *	- stroke_create()
 * 
 * @ingroup config
 */
struct connection_store_t {

	/**
	 * @brief Returns a connection definition identified by two hosts.
	 * 
	 * This call is usefull to get a connection identified by addresses.
	 * It may be used after kernel request for traffic protection.
	 * The returned connection gets created/cloned and therefore must
	 * be destroyed after usage.
	 * 
	 * @param this				calling object
	 * @param my_id				own address of connection
	 * @param other_id			others address of connection
	 * @return		
	 * 							- connection_t, if found
	 * 							- NULL otherwise
	 */
	connection_t *(*get_connection_by_hosts) (connection_store_t *this, host_t *my_host, host_t *other_host);
	
	/**
	 * @brief Returns a connection identified by its name.
	 * 
	 * This call is usefull to get a connection identified its
	 * name, as on an connection setup.
	 * 
	 * @param this				calling object
	 * @param name				name of the connection to get
	 * @return		
	 * 							- connection_t, if found
	 * 							- NULL otherwise
	 */
	connection_t *(*get_connection_by_name) (connection_store_t *this, char *name);
	
	/**
	 * @brief Add a connection to the store.
	 * 
	 * After a successful call, the connection is owned by the store and may 
	 * not be manipulated nor destroyed.
	 * 
	 * @param this				calling object
	 * @param connection		connection to add
	 * @return
	 * 							- SUCCESS, or
	 * 							- FAILED
	 */
	status_t (*add_connection) (connection_store_t *this, connection_t *connection);
	
	/**
	 * @brief Delete a connection from the store.
	 * 
	 * Remove a connection from the connection store, identified
	 * by the connections name.
	 * 
	 * @param this				calling object
	 * @param name				name of the connection to delete
	 * @return
	 * 							- SUCCESS, or
	 * 							- NOT_FOUND
	 */
	status_t (*delete_connection) (connection_store_t *this, char *name);
	
	/**
	 * @brief Log the connections stored in the store.
	 * 
	 * Depending on the implementation of the store, the store
	 * logs various information to the specified logger.
	 * If logger is NULL, the internal logger is used, if name is
	 * NULL, all connections are logged
	 * 
	 * @param this				calling object
	 * @param logger			logger to use for the log, or NULL
	 * @param name				name of the connection, or NULL
	 * @return
	 * 							- SUCCESS, or
	 * 							- FAILED
	 */
	void (*log_connections) (connection_store_t *this, logger_t *logger, char *name);
	
	/**
	 * @brief Destroys a connection_store_t object.
	 * 
	 * @param this 					calling object
	 */
	void (*destroy) (connection_store_t *this);
};

#endif /* CONNECTION_STORE_H_ */
