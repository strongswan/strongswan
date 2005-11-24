/**
 * @file signer.h
 * 
 * @brief Interface for signer_t.
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

#ifndef SIGNER_H_
#define SIGNER_H_

#include <types.h>
#include <definitions.h>

typedef enum integrity_algorithm_t integrity_algorithm_t;

/**
 * @brief Integrity algorithm, as in IKEv2 draft 3.3.2.
 * 
 */
enum integrity_algorithm_t {
	AUTH_UNDEFINED = 1024,
	AUTH_HMAC_MD5_96 = 1,
	AUTH_HMAC_SHA1_96 = 2,
	AUTH_DES_MAC = 3,
	AUTH_KPDK_MD5 = 4,
	AUTH_AES_XCBC_96 = 5
};

/** 
 * string mappings for integrity_algorithm_t
 */
extern mapping_t integrity_algorithm_m[];


typedef struct signer_t signer_t;

/**
 * @brief Generig interface for a symmetric signature algorithm.
 * 
 * @ingroup signers
 */
struct signer_t {
	/**
	 * @brief Generate a signature.
	 * 
	 * @param this			calling signer
	 * @param data			a chunk containing the data to sign
	 * @param[out] buffer	pointer where the signature will be written
	 * @return				
	 * 						- SUCCESS in any case
	 */
	status_t (*get_signature) (signer_t *this, chunk_t data, u_int8_t *buffer);
	
	/**
	 * @brief Generate a signature and allocate space for it.
	 * 
	 * @param this			calling signer
	 * @param data			a chunk containing the data to sign
	 * @param[out] chunk	chunk which will hold the allocated signature
	 * @return				
	 * 						- SUCCESS in any case
	 * 						- OUT_OF_RES if space could not be allocated
	 */
	status_t (*allocate_signature) (signer_t *this, chunk_t data, chunk_t *chunk);
	
	/**
	 * @brief Verify a signature.
	 * 
	 * @param this			calling signer
	 * @param data			a chunk containing the data to verify
	 * @param signature		a chunk containing the signature
	 * @param[out] vaild	set to TRUE, if signature is valid, to FALSE otherwise
	 * @return				
	 * 						- SUCCESS in any case
	 */
	status_t (*verify_signature) (signer_t *this, chunk_t data, chunk_t signature, bool *valid);
	
	/**
	 * @brief Get the block size of this signature algorithm.
	 * 
	 * @param this			calling signer
	 * @return				block size in bytes
	 */
	size_t (*get_block_size) (signer_t *this);
	
	/**
	 * @brief Set the key for this signer.
	 * 
	 * @param this			calling signer
	 * @param key			key to set
	 * @return
	 * 						- SUCCESS in any case
	 */
	status_t (*set_key) (signer_t *this, chunk_t key);
	
	/**
	 * @brief Destroys a signer object.
	 *
	* @param this			signer_t object to destroy
	 * @return 		
	 * 						- SUCCESS in any case
	 */
	status_t (*destroy) (signer_t *this);
};

/**
 * @brief Creates a new signer_t object.
 * 
 * @param integrity_algorithm	Algorithm to use for signing and verifying.
 * @return
 * 								- signer_t if successfully
 * 								- NULL if out of ressources or signer not supported
 * 
 * @ingroup signers
 */
signer_t *signer_create(integrity_algorithm_t integrity_algorithm);

#endif /*SIGNER_H_*/
