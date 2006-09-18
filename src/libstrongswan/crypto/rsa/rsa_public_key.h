/**
 * @file rsa_public_key.h
 * 
 * @brief Interface of rsa_public_key_t.
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

#ifndef RSA_PUBLIC_KEY_H_
#define RSA_PUBLIC_KEY_H_

#include <gmp.h>

#include <types.h>
#include <definitions.h>


typedef struct rsa_public_key_t rsa_public_key_t;

/**
 * @brief RSA public key with associated functions.
 * 
 * Currently only supports signature verification using
 * the EMSA encoding (see PKCS1)
 * 
 * @b Constructors:
 * - rsa_public_key_create_from_chunk()
 * - rsa_public_key_create_from_file()
 * - rsa_private_key_t.get_public_key()
 * 
 * @see rsa_private_key_t
 * 
 * @todo Implement getkey() and savekey()
 * 
 * @ingroup rsa
 */
struct rsa_public_key_t {

	/**
	 * @brief Verify a EMSA-PKCS1 encodined signature.
	 * 
	 * Processes the supplied signature with the RSAVP1 function,
	 * selects the hash algorithm form the resultign ASN1-OID and
	 * verifies the hash against the supplied data.
	 * 
	 * @param this				rsa_public_key to use
	 * @param data				data to sign
	 * @param signature			signature to verify
	 * @return
	 * 							- SUCCESS, if signature ok
	 * 							- INVALID_STATE, if key not set
	 * 							- NOT_SUPPORTED, if hash algorithm not supported
	 * 							- INVALID_ARG, if signature is not a signature
	 * 							- FAILED if signature invalid or unable to verify
	 */
	status_t (*verify_emsa_pkcs1_signature) (const rsa_public_key_t *this, chunk_t data, chunk_t signature);
	
	/**
	 * @brief Gets the key.
	 * 
	 * Currently uses a proprietary format which is only inteded
	 * for testing. This should be replaced with a proper
	 * ASN1 encoded key format, when charon gets the ASN1 
	 * capabilities.
	 * 
	 * @param this				calling object
	 * @param key				key (in a propriarity format)
	 * @return					
	 * 							- SUCCESS
	 * 							- INVALID_STATE, if key not set
	 */
	status_t (*get_key) (const rsa_public_key_t *this, chunk_t *key);
	
	/**
	 * @brief Saves a key to a file.
	 * 
	 * Not implemented!
	 * 
	 * @param this				calling object
	 * @param file				file to which the key should be written.
	 * @return					NOT_SUPPORTED
	 */
	status_t (*save_key) (const rsa_public_key_t *this, char *file);
	
	/**
	 * @brief Get the modulus of the key.
	 * 
	 * @param this				calling object
	 * @return					modulus (n) of the key
	 */
	mpz_t *(*get_modulus) (const rsa_public_key_t *this);
	
	/**
	 * @brief Get the size of the modulus in bytes.
	 * 
	 * @param this				calling object
	 * @return					size of the modulus (n) in bytes
	 */
	size_t (*get_keysize) (const rsa_public_key_t *this);

	/**
	 * @brief Get the keyid formed as the SHA-1 hash of a publicKeyInfo object.
	 * 
	 * @param this				calling object
	 * @return					keyid in the form of a SHA-1 hash
	 */
	chunk_t (*get_keyid) (const rsa_public_key_t *this);

	/**
	 * @brief Clone the public key.
	 * 
	 * @param this				public key to clone
	 * @return					clone of this
	 */
	rsa_public_key_t *(*clone) (const rsa_public_key_t *this);
	
	/**
	 * @brief Destroys the public key.
	 * 
	 * @param this				public key to destroy
	 */
	void (*destroy) (rsa_public_key_t *this);
};

/**
 * @brief Load an RSA public key from a chunk.
 * 
 * Load a key from a chunk, encoded in the more frequently
 * used publicKeyInfo object (ASN1 DER encoded).
 * 
 * @param chunk				chunk containing the DER encoded key
 * @return 					loaded rsa_public_key_t, or NULL
  * 
 * @ingroup rsa
 */
rsa_public_key_t *rsa_public_key_create_from_chunk(chunk_t chunk);

/**
 * @brief Load an RSA public key from a file.
 * 
 * Load a key from a file, which is either in binary
 * format (DER), or in PEM format. 
 * 
 * @param filename			filename which holds the key
 * @return 					loaded rsa_public_key_t, or NULL
 * 
 * @ingroup rsa
 */
rsa_public_key_t *rsa_public_key_create_from_file(char *filename);

#endif /*RSA_PUBLIC_KEY_H_*/
