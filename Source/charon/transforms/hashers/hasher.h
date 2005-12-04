/**
 * @file hasher.h
 * 
 * @brief Interface for hasher_t.
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


#include <types.h>

typedef enum hash_algorithm_t hash_algorithm_t;

/**
 * @brief Algorithms to use for hashing.
 */
enum hash_algorithm_t {
	HASH_MD2,
	HASH_MD5, /* supported */
	HASH_SHA1, /* supported */
	HASH_SHA256,
	HASH_SHA384,
	HASH_SHA512,
};

/**
 * string mappings for hash_algorithm_t
 */
extern mapping_t hash_algorithm_m[];


typedef struct hasher_t hasher_t;

/**
 * @brief Generic interface for all hash functions.
 * 
 * @b Constructors:
 * - hasher_create()
 * 
 * @see md5_hasher_t, sha1_hasher_t
 * 
 * @ingroup hashers
 */
struct hasher_t {
	/**
	 * @brief hash data and write it in the buffer
	 * 
	 * If the parameter hash is NULL, no result is written back
	 * an more data can be appended to already hashed data.
	 * If not, the result is written back and the hasher is reset.
	 * 
	 * @warning: the hash output parameter must hold at least
	 * hash_t.get_block_size bytes.
	 * 
	 * @param this			calling hasher
	 * @param data			data to hash
	 * @param [out]buffer	pointer where the hash will be written
	 */
	void (*get_hash) (hasher_t *this, chunk_t data, u_int8_t *hash);
	
	/**
	 * @brief hash data and allocate space for the hash
	 * 
	 * If the parameter hash is NULL, no result is written back
	 * an more data can be appended to already hashed data.
	 * If not, the result is written back and the hasher is reset.
	 * 
	 * @param this			calling hasher
	 * @param data			chunk with data to hash
	 * @param [out]hash		chunk which will hold allocated hash
	 */
	void (*allocate_hash) (hasher_t *this, chunk_t data, chunk_t *hash);
	
	/**
	 * @brief Get the block size of this hashing function.
	 * 
	 * @param this			calling hasher
	 * @return				block size in bytes
	 */
	size_t (*get_block_size) (hasher_t *this);
	
	/**
	 * @brief Resets the hashers state, which allows
	 * computation of a completly new hash.
	 * 
	 * @param this			calling hasher
	 */
	void (*reset) (hasher_t *this);
	
	/**
	 * @brief Destroys a hasher object.
	 *
	 * @param this 	hasher_t object to destroy
	 */
	void (*destroy) (hasher_t *this);
};

/**
 * @brief Generic interface to create a hasher_t.
 * 
 * @param hash_algorithm	Algorithm to use for hashing
 * @return
 * 							- hasher_t if successfully
 * 							- NULL if algorithm not supported
 * 
 * @ingroup hashers
 */
hasher_t *hasher_create(hash_algorithm_t hash_algorithm);

#endif /*HASHER_H_*/
