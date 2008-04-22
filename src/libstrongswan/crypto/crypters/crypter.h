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
 * @defgroup crypter crypter
 * @{ @ingroup crypto
 */

#ifndef CRYPTER_H_
#define CRYPTER_H_

typedef enum encryption_algorithm_t encryption_algorithm_t;
typedef struct crypter_t crypter_t;

#include <library.h>

/**
 * Encryption algorithm, as in IKEv2 RFC 3.3.2.
 */
enum encryption_algorithm_t {
	ENCR_UNDEFINED = 1024,
	ENCR_DES_IV64 = 1,
	ENCR_DES = 2,
	ENCR_3DES = 3,
	ENCR_RC5 = 4,
	ENCR_IDEA = 5,
	ENCR_CAST = 6,
	ENCR_BLOWFISH = 7,
	ENCR_3IDEA = 8,
	ENCR_DES_IV32 = 9,
	ENCR_NULL = 11,
	ENCR_AES_CBC = 12,
	ENCR_AES_CTR = 13
};

/**
 * enum name for encryption_algorithm_t.
 */
extern enum_name_t *encryption_algorithm_names;

/**
 * Generic interface for symmetric encryption algorithms.
 */
struct crypter_t {
	
	/**
	 * Encrypt a chunk of data and allocate space for the encrypted value.
	 *
	 * The length of the iv must equal to get_block_size(), while the length
	 * of data must be a multiple it.
	 *
	 * @param data			data to encrypt
	 * @param iv			initializing vector
	 * @param encrypted		chunk to allocate encrypted data
	 */
	void (*encrypt) (crypter_t *this, chunk_t data, chunk_t iv,
					 chunk_t *encrypted);
	
	/**
	 * Decrypt a chunk of data and allocate space for the decrypted value.
	 *
	 * The length of the iv must equal to get_block_size(), while the length
	 * of data must be a multiple it.
	 * 
	 * @param data			data to decrypt
	 * @param iv			initializing vector
	 * @param encrypted		chunk to allocate decrypted data
	 */
	void (*decrypt) (crypter_t *this, chunk_t data, chunk_t iv,
					 chunk_t *decrypted);

	/**
	 * Get the block size of the crypto algorithm.
	 * 
	 * @return					block size in bytes
	 */
	size_t (*get_block_size) (crypter_t *this);

	/**
	 * Get the key size of the crypto algorithm.
	 * 
	 * @return					key size in bytes
	 */
	size_t (*get_key_size) (crypter_t *this);
	
	/**
	 * Set the key.
	 *
	 * The length of the key must match get_key_size().
	 *
	 * @param key				key to set
	 */
	void (*set_key) (crypter_t *this, chunk_t key);
	
	/**
	 * Destroys a crypter_t object.
	 */
	void (*destroy) (crypter_t *this);
};

#endif /*CRYPTER_H_ @} */
