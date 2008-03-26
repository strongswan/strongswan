/*
 * Copyright (C) 2008 Martin Willi
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
 *
 * $Id$
 */

/**
 * @defgroup stroke_shared_key stroke_shared_key
 * @{ @ingroup stroke
 */

#ifndef STROKE_SHARED_KEY_H_
#define STROKE_SHARED_KEY_H_

#include <utils/identification.h>
#include <credentials/keys/shared_key.h>

typedef struct stroke_shared_key_t stroke_shared_key_t;

/**
 * Shared key implementation for keys read from ipsec.secrets
 */
struct stroke_shared_key_t {

	/**
	 * Implements the shared_key_t interface.
	 */
	shared_key_t shared;
	
	/**
	 * Add an owner to the key.
	 *
	 * @param owner		owner to add
	 */
	void (*add_owner)(stroke_shared_key_t *this, identification_t *owner);
	
	/**
	 * Check if a key has a specific owner.
	 *
	 * @param owner		owner to check
	 * @return			best match found
	 */
	id_match_t (*has_owner)(stroke_shared_key_t *this, identification_t *owner);	
};

/**
 * Create a stroke_shared_key instance.
 */
stroke_shared_key_t *stroke_shared_key_create(shared_key_type_t type, chunk_t key);

#endif /* STROKE_SHARED_KEY_H_ @}*/
