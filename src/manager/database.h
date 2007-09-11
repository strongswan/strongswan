/**
 * @file database.h
 * 
 * @brief Interface of database_t.
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

#ifndef DATABASE_H_
#define DATABASE_H_

#include <enumerator.h>


typedef struct database_t database_t;

/**
 * @brief Persistent database.
 */
struct database_t {

	/**
	 * @brief Try to log in using specified credentials.
	 *
	 * @param username			username
	 * @param password			plaintext password
	 * @return					user ID if login good, 0 otherwise
	 */
	int (*login)(database_t *this, char *username, char *password);
	
	/**
	 * @brief Create an iterator over the gateways.
	 *
	 * enumerate() arguments: int id, char *name, int port, char *address
	 * If port is 0, address is a Unix socket address.
	 *
	 * @param user				user Id
	 * @return					enumerator
	 */
	enumerator_t* (*create_gateway_enumerator)(database_t *this, int user);	

	/**
     * @brief Destroy a database instance.
     */
    void (*destroy)(database_t *this);
};

/**
 * @brief Create a database instance.
 *
 * @param dbfile				SQLite database file
 */
database_t *database_create(char *dbfile);

#endif /* DATABASE_H_ */
