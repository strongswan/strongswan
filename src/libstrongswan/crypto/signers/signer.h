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
 
/**
 * @defgroup signer signer
 * @{ @ingroup crypto
 */

#ifndef SIGNER_H_
#define SIGNER_H_

typedef enum integrity_algorithm_t integrity_algorithm_t;
typedef struct signer_t signer_t;

#include <library.h>

/**
 * Integrity algorithm, as in IKEv2 RFC 3.3.2.
 *
 * Algorithms not specified in IKEv2 are allocated in private use space.
 */
enum integrity_algorithm_t {
	AUTH_UNDEFINED = 1024,
	/** Implemented via hmac_signer_t */
	AUTH_HMAC_MD5_96 = 1,
	/** Implemented via hmac_signer_t */
	AUTH_HMAC_SHA1_96 = 2,
	AUTH_DES_MAC = 3,
	AUTH_KPDK_MD5 = 4,
	AUTH_AES_XCBC_96 = 5,
	/** RFC4595, used for RADIUS */
	AUTH_HMAC_MD5_128 = 6,
	/** Implemented via hmac_signer_t */
	AUTH_HMAC_SHA2_256_128 = 12,
	/** Implemented via hmac_signer_t */
	AUTH_HMAC_SHA2_384_192 = 13,
	/** Implemented via hmac_signer_t */
	AUTH_HMAC_SHA2_512_256 = 14,
	/** Implemented via hmac_signer_t */
	AUTH_HMAC_SHA1_128 = 1025,
};

/**
 * enum names for integrity_algorithm_t.
 */
extern enum_name_t *integrity_algorithm_names;

/**
 * Generig interface for a symmetric signature algorithm.
 */
struct signer_t {
	/**
	 * Generate a signature.
	 *
	 * If buffer is NULL, data is processed and prepended to a next call until
	 * buffer is a valid pointer.
	 * 
	 * @param data		a chunk containing the data to sign
	 * @param buffer	pointer where the signature will be written
	 */
	void (*get_signature) (signer_t *this, chunk_t data, u_int8_t *buffer);
	
	/**
	 * Generate a signature and allocate space for it.
	 *
	 * If chunk is NULL, data is processed and prepended to a next call until
	 * chunk is a valid chunk pointer.
	 * 
	 * @param data		a chunk containing the data to sign
	 * @param chunk		chunk which will hold the allocated signature
	 */
	void (*allocate_signature) (signer_t *this, chunk_t data, chunk_t *chunk);
	
	/**
	 * Verify a signature.
	 * 
	 * @param data		a chunk containing the data to verify
	 * @param signature	a chunk containing the signature
	 * @return			TRUE, if signature is valid, FALSE otherwise
	 */
	bool (*verify_signature) (signer_t *this, chunk_t data, chunk_t signature);
	
	/**
	 * Get the block size of this signature algorithm.
	 * 
	 * @return			block size in bytes
	 */
	size_t (*get_block_size) (signer_t *this);
	
	/**
	 * Get the key size of the signature algorithm.
	 * 
	 * @return			key size in bytes
	 */
	size_t (*get_key_size) (signer_t *this);
	
	/**
	 * Set the key for this object.
	 * 
	 * @param key		key to set
	 */
	void (*set_key) (signer_t *this, chunk_t key);
	
	/**
	 * Destroys a signer_t object.
	 */
	void (*destroy) (signer_t *this);
};

#endif /** SIGNER_H_ @}*/
