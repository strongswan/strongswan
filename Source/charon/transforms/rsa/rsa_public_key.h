/**
 * @file rsa_public_key.h
 * 
 * @brief Interface of rsa_public_key_t.
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
 * - rsa_public_key_create()
 * 
 * @see rsa_private_key_t
 * 
 * @ingroup rsa
 */
struct rsa_public_key_t {

	/**
	 * @bief Verify a EMSA-PKCS1 encodined signature.
	 * 
	 * Processes the supplied signature with the RSAVP1 function,
	 * selects the hash algorithm form the resultign ASN1-OID and
	 * verifies the hash against the supplied data.
	 * 
	 * @param this				rsa_private_key to use
	 * @param data				data to sign
	 * @param signature			signature to verify
	 * @return
	 * 							- SUCCESS, if signature ok
	 * 							- INVALID_STATE, if key not set
	 * 							- NOT_SUPPORTED, if hash algorithm not supported
	 * 							- INVALID_ARG, if signature is not a signature
	 * 							- FAILED if signature invalid or unable to verify
	 */
	status_t (*verify_emsa_pkcs1_signature) (rsa_public_key_t *this, chunk_t data, chunk_t signature);
	
	/**
	 * @brief Set the key.
	 * 
	 * Currently uses a proprietary format which is only inteded
	 * for testing. This should be replaced with a proper
	 * ASN1 encoded key format, when charon gets the ASN1 
	 * capabilities.
	 * 
	 * @param this				calling object
	 * @param key				key (in a propriarity format)
	 * @return					currently SUCCESS in any case
	 */
	status_t (*set_key) (rsa_public_key_t *this, chunk_t key);
	
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
	status_t (*get_key) (rsa_public_key_t *this, chunk_t *key);
	
	/**
	 * @brief Loads a key from a file.
	 * 
	 * Not implemented!
	 * 
	 * @param this				calling object
	 * @param file				file from which key should be read
	 * @return					NOT_SUPPORTED
	 */
	status_t (*load_key) (rsa_public_key_t *this, char *file);
	
	/**
	 * @brief Saves a key to a file.
	 * 
	 * Not implemented!
	 * 
	 * @param this				calling object
	 * @param file				file to which the key should be written.
	 * @return					NOT_SUPPORTED
	 */
	status_t (*save_key) (rsa_public_key_t *this, char *file);
	
	/**
	 * @brief Destroys the public key.
	 * 
	 * @param this				public key to destroy
	 */
	void (*destroy) (rsa_public_key_t *this);
};

/**
 * @brief Create a public key without any key inside.
 * 
 * @return created rsa_public_key_t.
 * 
 * @ingroup rsa
 */
rsa_public_key_t *rsa_public_key_create();

#endif /*RSA_PUBLIC_KEY_H_*/
