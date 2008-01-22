/**
 * @file rsa_private_key.h
 * 
 * @brief Interface of rsa_private_key_t.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2007-2008 Andreas Steffen
 *
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
 * RCSID $Id$
 */

#ifndef RSA_PRIVATE_KEY_H_
#define RSA_PRIVATE_KEY_H_

typedef struct rsa_private_key_t rsa_private_key_t;

#include <library.h>
#include <crypto/rsa/rsa_public_key.h>
#include <crypto/hashers/hasher.h>

/**
 * @brief RSA private key with associated functions.
 *
 * Currently only supports signing using EMSA encoding.
 *
 * @b Constructors:
 *  - rsa_private_key_create()
 *  - rsa_private_key_create_from_chunk()
 *  - rsa_private_key_create_from_file()
 * 
 * @see rsa_public_key_t
 *
 * @ingroup rsa
 */
struct rsa_private_key_t {

	/**
	 * @brief Decrypt a data block based on EME-PKCS1 encoding.
	 * 
	 * 
	 * @param this				calling object
	 * @param data				encrypted input data
	 * @param out				decrypted output data
	 * @return
	 * 							- SUCCESS
	 * 							- FAILED if padding is not correct
	 */
	status_t (*pkcs1_decrypt) (rsa_private_key_t *this, chunk_t in, chunk_t *out);

	/**
	 * @brief Build a signature over a chunk using EMSA-PKCS1 encoding.
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
	 * @brief Writes an RSA private key to a file in PKCS#1 format.
	 *
	 * @param this				calling object
	 * @param filename			file to which the key should be written.
	 * @param force				if TRUE overwrite existing file
	 * @return					TRUE if successful - FALSE otherwise
	 */
	bool (*pkcs1_write) (rsa_private_key_t *this, const char *filename, bool force);
	
	/**
	 * @brief Create a rsa_public_key_t with the public part of the key.
	 * 
	 * @param this				calling object
	 * @return					public_key
	 */
	rsa_public_key_t *(*get_public_key) (rsa_private_key_t *this);
	
	/**
	 * @brief Check if a private key belongs to a public key.
	 * 
	 * Compares the public part of the private key with the
	 * public key, return TRUE if it equals.
	 * 
	 * @param this				private key
	 * @param public			public key
	 * @return					TRUE, if keys belong together
	 */
	bool (*belongs_to) (rsa_private_key_t *this, rsa_public_key_t *public);
	
	/**
	 * @brief Destroys the private key.
	 * 
	 * @param this				private key to destroy
	 */
	void (*destroy) (rsa_private_key_t *this);
};

/**
 * @brief Generate a new RSA key with specified key length.
 * 
 * @param key_size			size of the key in bits
 * @return 					generated rsa_private_key_t.
 * 
 * @ingroup rsa
 */
rsa_private_key_t *rsa_private_key_create(size_t key_size);

/**
 * @brief Load an RSA private key from a chunk.
 * 
 * Load a key from a chunk, encoded as described in PKCS#1
 * (ASN1 DER encoded).
 * 
 * @param chunk				chunk containing the DER encoded key
 * @return 					loaded rsa_private_key_t, or NULL
 * 
 * @ingroup rsa
 */
rsa_private_key_t *rsa_private_key_create_from_chunk(chunk_t chunk);

/**
 * @brief Load an RSA private key from a file.
 * 
 * Load a key from a file, which is either in a unencrypted binary
 * format (DER), or in a (encrypted) PEM format. The supplied 
 * passphrase is used to decrypt an ecrypted key.
 * 
 * @param filename			filename which holds the key
 * @param passphrase		optional passphase for decryption, can be NULL
 * @return 					loaded rsa_private_key_t, or NULL
 * 
 * @todo Implement PEM file loading
 * @todo Implement key decryption
 * 
 * @ingroup rsa
 */
rsa_private_key_t *rsa_private_key_create_from_file(char *filename, chunk_t *passphrase);

#endif /*RSA_PRIVATE_KEY_H_*/
