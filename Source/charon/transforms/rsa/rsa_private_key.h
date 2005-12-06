/**
 * @file rsa_private_key.h
 * 
 * @brief Interface of rsa_private_key_t.
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

#ifndef RSA_PRIVATE_KEY_H_
#define RSA_PRIVATE_KEY_H_

#include <types.h>
#include <definitions.h>
#include <transforms/rsa/rsa_public_key.h>
#include <transforms/hashers/hasher.h>


typedef struct rsa_private_key_t rsa_private_key_t;

/**
 * @brief RSA private key with associated functions.
 * 
 * Currently only supports signing using EMSA encoding.
 * 
 * @b Constructors:
 *  - rsa_private_key_create()
 * 
 * @see rsa_public_key_t
 * 
 * @todo Implement proper key set/get load/save methods using ASN1.
 *
 * @ingroup rsa
 */
struct rsa_private_key_t {

	/**
	 * @bief Build a signature over a chunk using EMSA-PKCS1 encoding.
	 * 
	 * This signature creates a hash using the specified hash algorithm, concatenates
	 * it with an ASN1-OID of the hash algorithm and runs the RSASP1 function
	 * on it.
	 * 
	 * @param this				calling object
	 * @param hash_algorithm	hash algorithm to use for hashing
	 * @param data				data to sign
	 * @param[out] signature	allocated signature
	 * @return
	 * 							- SUCCESS
	 * 							- INVALID_STATE, if key not set
	 * 							- NOT_SUPPORTED, if hash algorithm not supported
	 */
	status_t (*build_emsa_pkcs1_signature) (rsa_private_key_t *this, hash_algorithm_t hash_algorithm, chunk_t data, chunk_t *signature);
	
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
	status_t (*set_key) (rsa_private_key_t *this, chunk_t key);
	
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
	status_t (*get_key) (rsa_private_key_t *this, chunk_t *key);
	
	/**
	 * @brief Loads a key from a file.
	 * 
	 * Not implemented!
	 * 
	 * @param this				calling object
	 * @param file				file from which key should be read
	 * @return					NOT_SUPPORTED
	 */
	status_t (*load_key) (rsa_private_key_t *this, char *file);
	
	/**
	 * @brief Saves a key to a file.
	 * 
	 * Not implemented!
	 * 
	 * @param this				calling object
	 * @param file				file to which the key should be written.
	 * @return					NOT_SUPPORTED
	 */
	status_t (*save_key) (rsa_private_key_t *this, char *file);
	
	/**
	 * @brief Generate a new key.
	 * 
	 * Generates a new private_key with specified key size
	 * 
	 * @param this				calling object
	 * @param key_size			size of the key in bits
	 * @return					
	 * 							- SUCCESS
	 * 							- INVALID_ARG if key_size invalid
	 */
	status_t (*generate_key) (rsa_private_key_t *this, size_t key_size);
	
	/**
	 * @brief Create a rsa_public_key_t with the public
	 * parts of the key.
	 * 
	 * @param this				calling object
	 * @return					public_key
	 */
	rsa_public_key_t *(*get_public_key) (rsa_private_key_t *this);
	
	/**
	 * @brief Destroys the private key.
	 * 
	 * @param this				private key to destroy
	 */
	void (*destroy) (rsa_private_key_t *this);
};

/**
 * @brief Create a new rsa_private_key without
 * any key inside.
 * 
 * @return created rsa_private_key_t.
 * 
 * @ingroup rsa
 */
rsa_private_key_t *rsa_private_key_create();

#endif /*RSA_PRIVATE_KEY_H_*/
