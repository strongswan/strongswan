/**
 * @file signer.h
 * 
 * @brief Interface for signer_t.
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

#ifndef SIGNER_H_
#define SIGNER_H_

#include <types.h>
#include <definitions.h>

typedef enum integrity_algorithm_t integrity_algorithm_t;

/**
 * @brief Integrity algorithm, as in IKEv2 RFC 3.3.2.
 * 
 * Currently only the following algorithms are implemented and therefore supported:
 * - AUTH_HMAC_MD5_96
 * - AUTH_HMAC_SHA1_96
 * 
 * @ingroup signers
 */
enum integrity_algorithm_t {
	AUTH_UNDEFINED = 1024,
	/** Implemented via hmac_signer_t */
	AUTH_HMAC_MD5_96 = 1,
	/** Implemented via hmac_signer_t */
	AUTH_HMAC_SHA1_96 = 2,
	AUTH_DES_MAC = 3,
	AUTH_KPDK_MD5 = 4,
	AUTH_AES_XCBC_96 = 5
};

/** 
 * String mappings for integrity_algorithm_t.
 */
extern mapping_t integrity_algorithm_m[];


typedef struct signer_t signer_t;

/**
 * @brief Generig interface for a symmetric signature algorithm.
 * 
 * @b Constructors:
 *  - signer_create()
 *  - hmac_signer_create()
 * 
 * @todo Implement more integrity algorithms
 * 
 * @ingroup signers
 */
struct signer_t {
	/**
	 * @brief Generate a signature.
	 * 
	 * @param this			calling object
	 * @param data			a chunk containing the data to sign
	 * @param[out] buffer	pointer where the signature will be written
	 */
	void (*get_signature) (signer_t *this, chunk_t data, u_int8_t *buffer);
	
	/**
	 * @brief Generate a signature and allocate space for it.
	 * 
	 * @param this			calling object
	 * @param data			a chunk containing the data to sign
	 * @param[out] chunk	chunk which will hold the allocated signature
	 */
	void (*allocate_signature) (signer_t *this, chunk_t data, chunk_t *chunk);
	
	/**
	 * @brief Verify a signature.
	 * 
	 * @param this			calling object
	 * @param data			a chunk containing the data to verify
	 * @param signature		a chunk containing the signature
	 * @return				TRUE, if signature is valid, FALSE otherwise
	 */
	bool (*verify_signature) (signer_t *this, chunk_t data, chunk_t signature);
	
	/**
	 * @brief Get the block size of this signature algorithm.
	 * 
	 * @param this			calling object
	 * @return				block size in bytes
	 */
	size_t (*get_block_size) (signer_t *this);
	
	/**
	 * @brief Get the key size of the signature algorithm.
	 * 
	 * @param this			calling object
	 * @return				key size in bytes
	 */
	size_t (*get_key_size) (signer_t *this);
	
	/**
	 * @brief Set the key for this object.
	 * 
	 * @param this			calling object
	 * @param key			key to set
	 */
	void (*set_key) (signer_t *this, chunk_t key);
	
	/**
	 * @brief Destroys a signer_t object.
	 *
	 * @param this			calling object
	 */
	void (*destroy) (signer_t *this);
};

/**
 * @brief Creates a new signer_t object.
 * 
 * @param integrity_algorithm	Algorithm to use for signing and verifying.
 * @return
 * 								- signer_t object
 * 								- NULL if signer not supported
 * 
 * @ingroup signers
 */
signer_t *signer_create(integrity_algorithm_t integrity_algorithm);

#endif /*SIGNER_H_*/
