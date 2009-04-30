/*
 * Copyright (C) 2007 Martin Willi
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
 * @defgroup private_key private_key
 * @{ @ingroup keys
 */

#ifndef PRIVATE_KEY_H_
#define PRIVATE_KEY_H_

typedef struct private_key_t private_key_t;

#include <utils/identification.h>
#include <credentials/keys/public_key.h>

/**
 * Abstract private key interface.
 */
struct private_key_t {

	/**
	 * Get the key type.
	 *
	 * @return			type of the key
	 */
	key_type_t (*get_type)(private_key_t *this);

	/**
	 * Create a signature over a chunk of data.
	 *
	 * @param scheme	signature scheme to use
	 * @param data		chunk of data to sign
	 * @param signature	where to allocate created signature
	 * @return			TRUE if signature created
	 */
	bool (*sign)(private_key_t *this, signature_scheme_t scheme, 
				 chunk_t data, chunk_t *signature);
	/**
	 * Decrypt a chunk of data.
	 *
	 * @param crypto	chunk containing encrypted data
	 * @param plain		where to allocate decrypted data
	 * @return			TRUE if data decrypted and plaintext allocated
	 */
	bool (*decrypt)(private_key_t *this, chunk_t crypto, chunk_t *plain);
	
	/**
	 * Get the strength of the key in bytes.
	 * 
	 * @return			strength of the key in bytes
	 */
	size_t (*get_keysize) (private_key_t *this);

	/**
	 * Get a unique key identifier, such as a hash over the public key.
	 * 
	 * @param type		type of the key ID to get
	 * @return			unique ID of the key as identification_t, or NULL
	 */
	identification_t* (*get_id) (private_key_t *this, id_type_t type);
	
	/**
	 * Get the public part from the private key.
	 *
	 * @return			public key
	 */
	public_key_t* (*get_public_key)(private_key_t *this);
	
	/**
	 * Check if a private key belongs to a public key.
	 * 
	 * @param public	public key
	 * @return			TRUE, if keys belong together
	 */
	bool (*belongs_to) (private_key_t *this, public_key_t *public);
	
	/**
	 * Get an encoded form of the private key.
	 *
	 * @todo Do we need a encoding type specification?
	 *
	 * @return			allocated chunk containing encoded private key
	 */
	chunk_t (*get_encoding)(private_key_t *this);	
	
	/**
	 * Increase the refcount to this private key.
	 *
	 * @return			this, with an increased refcount
	 */
	private_key_t* (*get_ref)(private_key_t *this);
		
	/**
     * Decrease refcount, destroy private_key if no more references.
     */
    void (*destroy)(private_key_t *this);
};

#endif /** PRIVATE_KEY_H_ @}*/
