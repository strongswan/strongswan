/**
 * @file crypter.h
 * 
 * @brief Interface crypter_t
 * 
 */

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
 */

#ifndef CRYPTER_H_
#define CRYPTER_H_

#include <types.h>

typedef enum encryption_algorithm_t encryption_algorithm_t;

/**
 * @brief Encryption algorithm, as in IKEv2 RFC 3.3.2.
 * 
 * Currently only the following algorithms are implemented:
 * - ENCR_AES_CBC
 * - ENCR_DES
 * - ENCR_3DES
 * 
 * @ingroup crypters
 */
enum encryption_algorithm_t {
	ENCR_UNDEFINED = 1024,
	ENCR_DES_IV64 = 1,
	/** Implemented in class des_crypter_t */
	ENCR_DES = 2,
	/** Implemented in class des_crypter_t */
	ENCR_3DES = 3,
	ENCR_RC5 = 4,
	ENCR_IDEA = 5,
	ENCR_CAST = 6,
	ENCR_BLOWFISH = 7,
	ENCR_3IDEA = 8,
	ENCR_DES_IV32 = 9,
	ENCR_NULL = 11,
	/** Implemented in class aes_cbc_crypter_t */
	ENCR_AES_CBC = 12,
	ENCR_AES_CTR = 13
};

/** 
 * String mappings for encryption_algorithm_t.
 */
extern mapping_t encryption_algorithm_m[];


typedef struct crypter_t crypter_t;

/**
 * @brief Generic interface for symmetric encryption algorithms.
 * 
 * @b Constructors:
 *  - crypter_create()
 * 
 * @ingroup crypters
 */
struct crypter_t {
	
	/**
	 * @brief Encrypt a chunk of data and allocate space for the encrypted value.
	 *
	 * @param this				calling object
	 * @param data				data to encrypt
	 * @param iv				initializing vector
	 * @param[out] encrypted	pointer where the encrypted bytes will be written
	 * @return
	 * 							- SUCCESS
	 * 							- INVALID_ARG if data size not a multiple of block size
	 */
	status_t (*encrypt) (crypter_t *this, chunk_t data, chunk_t iv, chunk_t *encrypted);
	
	/**
	 * @brief Decrypt a chunk of data and allocate space for the decrypted value.
	 * 
	 * @param this				calling object
	 * @param data				data to decrypt
	 * @param iv				initializing vector
	 * @param[out] encrypted	pointer where the decrypted bytes will be written
	 * @return
	 * 							- SUCCESS
	 * 							- INVALID_ARG if data size not a multiple of block size
	 */
	status_t (*decrypt) (crypter_t *this, chunk_t data, chunk_t iv, chunk_t *decrypted);

	/**
	 * @brief Get the block size of this crypter_t object.
	 * 
	 * @param this				calling object
	 * @return					block size in bytes
	 */
	size_t (*get_block_size) (crypter_t *this);

	/**
	 * @brief Get the key size of this crypter_t object.
	 * 
	 * @param this				calling object
	 * @return					key size in bytes
	 */
	size_t (*get_key_size) (crypter_t *this);
	
	/**
	 * @brief Set the key for this crypter_t object.
	 * 
	 * @param this				calling object
	 * @param key				key to set
	 * @return
	 * 							- SUCCESS
	 * 							- INVALID_ARG if key length invalid
	 */
	status_t (*set_key) (crypter_t *this, chunk_t key);
	
	/**
	 * @brief Destroys a crypter_t object.
	 *
	 * @param this 				calling object
	 */
	void (*destroy) (crypter_t *this);
};

/**
 * @brief Generic constructor for crypter_t objects.
 * 
 * Currently only the following algorithms are implemented:
 * - ENCR_AES_CBC
 * - ENCR_DES
 * - ENCR_3DES
 * 
 * The key_size is ignored for algorithms with fixed key size.
 * 
 * @param encryption_algorithm	Algorithm to use for crypter
 * @param key_size 				size of the key in bytes
 * @return
 * 								- crypter_t object
 * 								- NULL if encryption algorithm/key_size is not supported
 */
crypter_t *crypter_create(encryption_algorithm_t encryption_algorithm, size_t key_size);

#endif /*CRYPTER_H_*/
