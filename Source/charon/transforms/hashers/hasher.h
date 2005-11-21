/**
 * @file hasher.h
 * 
 * @brief Generic interface for hash functions
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

#ifndef HASHER_H_
#define HASHER_H_


#include "../../types.h"

/**
 * algorithms to use for hashing
 */
typedef enum hash_algorithm_e hash_algorithm_t;

enum hash_algorithm_e {
	SHA1,
	MD5
};


/**
 * Object representing a hasher
 */
typedef struct hasher_s hasher_t;

struct hasher_s {
	/**
	 * @brief hash data and write it in the buffer
	 * 
	 * @param this			calling hasher
	 * @param data			data to hash
	 * @param [out]buffer	pointer where the hash will be written
	 * @return				
	 * 						- SUCCESS in any case
	 */
	status_t (*get_hash) (hasher_t *this, chunk_t data, u_int8_t *buffer);
	
	/**
	 * @brief hash data and allocate space for the hash
	 * 
	 * @param this			calling hasher
	 * @param seed			a chunk containing the seed for the next bytes
	 * @param [out]hash		chunk which will hold allocated hash
	 * @return				
	 * 						- SUCCESS in any case
	 * 						- OUT_OF_RES if space could not be allocated
	 */
	status_t (*allocate_hash) (hasher_t *this, chunk_t data, chunk_t *hash);
	
	/**
	 * @brief get the block size of this hashing function
	 * 
	 * @param this			calling hasher
	 * @return				block size in bytes
	 */
	size_t (*get_block_size) (hasher_t *this);
	
	/**
	 * @brief Destroys a hasher object.
	 *
	 * @param this 	hasher_t object to destroy
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*destroy) (hasher_t *this);
};

/**
 * Creates a new hasher_t object
 * 
 * @param hash_algorithm			Algorithm to use for hashing
 * @return
 * 									- hasher_t if successfully
 * 									- NULL if out of ressources 
 */
hasher_t *hasher_create(hash_algorithm_t hash_algorithm);

#endif /*HASHER_H_*/
