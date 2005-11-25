/**
 * @file randomizer.h
 * 
 * @brief Interface of randomizer_t.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#ifndef RANDOMIZER_H_
#define RANDOMIZER_H_

#include <types.h>

typedef struct randomizer_t randomizer_t;

/**
 * @brief Class used to get random and pseudo random values.
 *
 * This class is thread save as file system read calls are thread save.
 * 
 * @ingroup utils
 */
struct randomizer_t {
	
	/**
	 * @brief Reads a specific number of bytes from random device.
	 * 
	 * @param this 					calling randomizer_t object
	 * @param bytes					number of bytes to read
	 * @param[out] buffer			pointer to buffer where to write the data in.
	 * 								Size of buffer has to be at least bytes.
	 * @return
	 * 								- SUCCESS
	 * 								- FAILED if random device could not be opened
	 */
	status_t (*get_random_bytes) (randomizer_t *this,size_t bytes, u_int8_t *buffer);
	
	/**
	 * @brief Allocates space and writes in random bytes.
	 * 
	 * @param this 					calling randomizer_t object
	 * @param bytes					number of bytes to allocate
	 * @param[out] chunk				chunk which will hold the allocated random bytes
	 * @return
	 * 								- SUCCESS
	 * 								- OUT_OF_RES
	 * 								- FAILED if random device could not be opened
	 */	
	status_t (*allocate_random_bytes) (randomizer_t *this, size_t bytes, chunk_t *chunk);
	
	/**
	 * @brief Reads a specific number of bytes from pseudo random device.
	 * 
	 * @param this 					calling randomizer_t object
	 * @param bytes					number of bytes to read
	 * @param[out] buffer			pointer to buffer where to write the data in.
	 * 								size of buffer has to be at least bytes.
	 * @return
	 * 								- SUCCESS
	 * 								- FAILED if random device could not be opened
	 */
	status_t (*get_pseudo_random_bytes) (randomizer_t *this,size_t bytes, u_int8_t *buffer);
	
	/**
	 * @brief Allocates space and writes in pseudo random bytes.
	 * 
	 * @param this 					calling randomizer_t object
	 * @param bytes					number of bytes to allocate
	 * @param[out] chunk				chunk which will hold the allocated random bytes
	 * @return
	 * 								- SUCCESS
	 * 								- OUT_OF_RES
	 * 								- FAILED if random device could not be opened
	 */	
	status_t (*allocate_pseudo_random_bytes) (randomizer_t *this, size_t bytes, chunk_t *chunk);

	/**
	 * @brief Destroys a randomizer_t object.
	 *
	 * @param this 	randomizer_t object to destroy
	 * @return 		SUCCESS in any case
	 */
	status_t (*destroy) (randomizer_t *this);
};

/**
 * @brief Creates a randomizer_t object
 * 
 * @return			
 * 					- created randomizer_t, or
 * 					- NULL if failed
 * 
 * @ingroup utils
 */
randomizer_t *randomizer_create();

/**
 * @brief Creates an randomizer_t object with specific random device names.
 * 
 * @param random_dev_name	device name for random values, etc /dev/random
 * @param prandom_dev_name	device name for pseudo random values, etc /dev/urandom
 * @return					
 *	 						- created randomizer_t
 * 							- NULL if out of ressources
 * 
 * @ingroup utils
 */
randomizer_t *randomizer_create_on_devices(char * random_dev_name,char * prandom_dev_name);

#endif /*RANDOMIZER_H_*/
