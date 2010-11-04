/*
 * Copyright (C) 2010 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup tnccs_manager tnccs_manager
 * @{ @ingroup tnccs
 */

#ifndef TNCCS_MANAGER_H_
#define TNCCS_MANAGER_H_

#include "tnccs.h"

typedef struct tnccs_manager_t tnccs_manager_t;

/**
 * The TNCCS manager manages all TNCCS implementations and creates instances.
 *
 * A plugin registers its implemented TNCCS protocol with the manager by
 * providing type and a constructor function. The manager then creates
 * TNCCS protocol instances via the provided constructor.
 */
struct tnccs_manager_t {

	/**
	 * Register a TNCCS protocol implementation.
	 *
	 * @param type			TNCCS protocol type
	 * @param constructor	constructor, returns a TNCCS protocol implementation
	 */
	void (*add_method)(tnccs_manager_t *this, tnccs_type_t type,
					   tnccs_constructor_t constructor);

	/**
	 * Unregister a TNCCS protocol implementation using it's constructor.
	 *
	 * @param constructor	constructor function to remove, as added in add_method
	 */
	void (*remove_method)(tnccs_manager_t *this, tnccs_constructor_t constructor);

	/**
	 * Create a new TNCCS protocol instance.
	 *
	 * @param type			type of the TNCCS protocol
	 * @param is_server		TRUE if TNC Server, FALSE if TNC Client
	 * @return				TNCCS protocol instance, NULL if no constructor found
	 */
	tnccs_t* (*create_instance)(tnccs_manager_t *this, tnccs_type_t type,
								bool is_server);

	/**
	 * Destroy a tnccs_manager instance.
	 */
	void (*destroy)(tnccs_manager_t *this);
};

/**
 * Create a tnccs_manager instance.
 */
tnccs_manager_t *tnccs_manager_create();

#endif /** TNCCS_MANAGER_H_ @}*/
