/**
 * @file crypter.h
 * 
 * @brief Generic interface for encryption algorithms
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

#ifndef CRYPTER_H_
#define CRYPTER_H_

#include "../../payloads/transform_substructure.h"


/**
 * Object representing a crypter object
 */
typedef struct crypter_s crypter_t;

struct crypter_s {
	/**
	 * @brief Encrypt a chunk of data and allocate space for 
	 * the encrypted value.
	 * 
	 * @param this				calling crypter
	 * @param data				data to encrypt
	 * @param [out]encrypted	pointer where the encrypted bytes will be written
	 * @return				
	 * 							- SUCCESS in any case
	 */
	status_t (*encrypt) (crypter_t *this, chunk_t data, chunk_t *encrypted);
	
	/**
	 * @brief Decrypt a chunk of data and allocate space for 
	 * the decrypted value.
	 * 
	 * @param this				calling crypter
	 * @param data				data to decrypt
	 * @param [out]encrypted	pointer where the decrypted bytes will be written
	 * @return				
	 * 							- SUCCESS in any case
	 */
	status_t (*decrypt) (crypter_t *this, chunk_t data, chunk_t *decrypted);

	/**
	 * @brief get the block size of this crypter
	 * 
	 * @param this			calling crypter
	 * @return				block size in bytes
	 */
	size_t (*get_block_size) (crypter_t *this);
	
	/**
	 * @brief Set the key for this crypter
	 * 
	 * @param this			calling crypter
	 * @return				block size in bytes
	 */
	status_t (*set_key) (crypter_t *this, chunk_t key);
	
	/**
	 * @brief Destroys a crypter object.
	 *
	 * @param this 	crypter_t object to destroy
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*destroy) (crypter_t *this);
};

/**
 * Creates a new crypter_t object
 * 
 * @param pseudo_random_function	Algorithm to use
 * @return
 * 									- crypter_t if successfully
 * 									- NULL if out of ressources or crypter not supported
 */
crypter_t *crypter_create(encryption_algorithm_t encryption_algorithm);

#endif /*CRYPTER_H_*/
