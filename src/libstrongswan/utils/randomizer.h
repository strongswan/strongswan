/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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
 * @defgroup randomizer randomizer
 * @{ @ingroup utils
 */

#ifndef RANDOMIZER_H_
#define RANDOMIZER_H_

typedef struct randomizer_t randomizer_t;

#include <library.h>

#ifndef DEV_RANDOM
/**
 * Device to read real random bytes
 */
# define DEV_RANDOM "/dev/random"
#endif

#ifndef DEV_URANDOM
/**
 * Device to read pseudo random bytes
 */
# define DEV_URANDOM "/dev/urandom"
#endif

/**
 * Class used to get random and pseudo random values.
 */
struct randomizer_t {
	
	/**
	 * Reads a specific number of bytes from random device.
	 *
	 * @param bytes			number of bytes to read
	 * @param buffer		pointer to buffer where to write the data in.
	 * @return				SUCCESS, or FAILED
	 */
	status_t (*get_random_bytes) (randomizer_t *this,
								  size_t bytes, u_int8_t *buffer);
	
	/**
	 * Allocates space and writes in random bytes.
	 * 
	 * @param bytes			number of bytes to allocate
	 * @param chunk			chunk which will hold the allocated random bytes
	 * @return				SUCCESS, or FAILED
	 */	
	status_t (*allocate_random_bytes) (randomizer_t *this,
									   size_t bytes, chunk_t *chunk);
	
	/**
	 * Reads a specific number of bytes from pseudo random device.
	 * 
	 * @param bytes			number of bytes to read
	 * @param buffer		pointer to buffer where to write the data in.
	 * @return				SUCCESS, or FAILED
	 */
	status_t (*get_pseudo_random_bytes) (randomizer_t *this,size_t bytes, u_int8_t *buffer);
	
	/**
	 * Allocates space and writes in pseudo random bytes.
	 * 
	 * @param bytes			number of bytes to allocate
	 * @param chunk			chunk which will hold the allocated random bytes
	 * @return				SUCCESS, or FAILED
	 */	
	status_t (*allocate_pseudo_random_bytes) (randomizer_t *this, size_t bytes, chunk_t *chunk);

	/**
	 * Destroys a randomizer_t object.
	 */
	void (*destroy) (randomizer_t *this);
};

/**
 * Creates a randomizer_t object.
 * 
 * @return	created randomizer_t
 */
randomizer_t *randomizer_create(void);

#endif /*RANDOMIZER_H_ @} */
