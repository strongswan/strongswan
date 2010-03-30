/*
 * Copyright (C) 2010 Tobias Brunner
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

/**
 * @defgroup whack_attribute
 * @{ @ingroup pluto
 */

#ifndef WHACK_ATTRIBUTE_H_
#define WHACK_ATTRIBUTE_H_

#include <whack.h>
#include <attributes/attribute_provider.h>

typedef struct whack_attribute_t whack_attribute_t;

/**
 * Whack attribute provider (basically an in-memory IP address pool)
 */
struct whack_attribute_t {

	/**
	 * Implements attribute provider interface
	 */
	attribute_provider_t provider;

	/**
	 * Add a virtual IP address pool.
	 *
	 * @param name		name of the pool
	 * @param right		"right" end of whack message
	 * @return			TRUE, if the pool was successfully added
	 */
	bool (*add_pool)(whack_attribute_t *this, const char *name,
					 const whack_end_t *right);

	/**
	 * Remove a virtual IP address pool.
	 *
	 * @param name		name of the pool
	 */
	void (*del_pool)(whack_attribute_t *this, char *name);

	/**
	 * Create an enumerator over installed pools.
	 *
	 * Enumerator enumerates over
	 * char *pool, u_int size, u_int offline, u_int online.
	 *
	 * @return			enumerator
	 */
	enumerator_t* (*create_pool_enumerator)(whack_attribute_t *this);

	/**
	 * Create an enumerator over the leases of a pool.
	 *
	 * Enumerator enumerates over
	 * identification_t *id, host_t *address, bool online
	 *
	 * @param name		name of the pool to enumerate
	 * @return			enumerator, NULL if pool not found
	 */
	enumerator_t* (*create_lease_enumerator)(whack_attribute_t *this,
											 char *name);
};

/**
 * Global object to manage pools. Set between calls to
 * whack_attribute_initialize() and whack_attribute_finalize().
 */
extern whack_attribute_t *whack_attr;

/**
 * Initialize the whack attribute provider
 */
void whack_attribute_initialize();

/**
 * Finalize the whack attribute provider
 */
void whack_attribute_finalize();

#endif /** WHACK_ATTRIBUTE_H_ @}*/
