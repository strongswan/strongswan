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
 *
 * $Id$
 */
 
/**
 * @defgroup public_key public_key
 * @{ @ingroup keys
 */

#ifndef PUBLIC_KEY_H_
#define PUBLIC_KEY_H_

typedef struct public_key_t public_key_t;
typedef enum key_type_t key_type_t;
typedef enum key_id_type_t key_id_type_t;
typedef enum signature_scheme_t signature_scheme_t;

#include <library.h>
#include <utils/identification.h>

/**
 * Type of a key pair, the used crypto system
 */
enum key_type_t {
	/** key type wildcard */
	KEY_ANY,
	/** RSA crypto system as in PKCS#1 */
	KEY_RSA,
	/** ECDSA as in ANSI X9.62 */
	KEY_ECDSA,
	/** DSS, ElGamal, ... */
};

/**
 * Enum names for key_type_t
 */
extern enum_name_t *key_type_names;

/**
 * Signature scheme for signature creation
 *
 * EMSA-PKCS1 signatures are from the PKCS#1 standard. They include
 * the ASN1-OID of the used hash algorithm.
 */
enum signature_scheme_t {
	/** default scheme of that underlying crypto system */
	SIGN_DEFAULT,
	/** EMSA-PKCS1 with MD5  */
	SIGN_RSA_EMSA_PKCS1_MD5,
	/** EMSA-PKCS1 signature as in PKCS#1 standard using SHA1 as hash.  */
	SIGN_RSA_EMSA_PKCS1_SHA1,
	/** EMSA-PKCS1 signature as in PKCS#1 standard using SHA256 as hash. */
	SIGN_RSA_EMSA_PKCS1_SHA256,
	/** EMSA-PKCS1 signature as in PKCS#1 standard using SHA384 as hash. */
	SIGN_RSA_EMSA_PKCS1_SHA384,
	/** EMSA-PKCS1 signature as in PKCS#1 standard using SHA512 as hash. */
	SIGN_RSA_EMSA_PKCS1_SHA512,
	/** ECDSA using SHA-1 as hash. */
	SIGN_ECDSA_WITH_SHA1,
	/** ECDSA with SHA-256 on the P-256 curve as in RFC 4754 */
	SIGN_ECDSA_256,
	/** ECDSA with SHA-384 on the P-384 curve as in RFC 4754 */
	SIGN_ECDSA_384,
	/** ECDSA with SHA-512 on the P-521 curve as in RFC 4754 */
	SIGN_ECDSA_521,
};

/**
 * Enum names for signature_scheme_t
 */
extern enum_name_t *signature_scheme_names;

/**
 * Abstract interface of a public key.
 */
struct public_key_t {

	/**
	 * Get the key type.
	 *
	 * @return			type of the key
	 */
	key_type_t (*get_type)(public_key_t *this);
	
	/**
	 * Verifies a signature against a chunk of data.
	 *
	 * @param scheme	signature scheme to use for verification, may be default
	 * @param data		data to check signature against
	 * @param signature	signature to check
	 * @return			TRUE if signature matches
	 */
	bool (*verify)(public_key_t *this, signature_scheme_t scheme, 
				   chunk_t data, chunk_t signature);
	
	/**
	 * Encrypt a chunk of data.
	 *
	 * @param crypto	chunk containing plaintext data
	 * @param plain		where to allocate encrypted data
	 * @return 			TRUE if data successfully encrypted
	 */
	bool (*encrypt)(public_key_t *this, chunk_t crypto, chunk_t *plain);
	
	/**
	 * Get the strength of the key in bytes.
	 * 
	 * @return			strength of the key in bytes
	 */
	size_t (*get_keysize) (public_key_t *this);

	/**
	 * Get a unique key identifier, such as a hash over the key.
	 * 
	 * @param type		type of the key ID to get
	 * @return			unique ID of the key as identification_t, or NULL
	 */
	identification_t* (*get_id) (public_key_t *this, id_type_t type);
	
	/**
	 * Get an encoded form of the key.
	 *
	 * @todo Do we need a encoding type specification?
	 *
	 * @return			allocated chunk containing encoded key
	 */
	chunk_t (*get_encoding)(public_key_t *this);	
	
	/**
	 * Increase the refcount of the key.
	 *
	 * @return			this with an increased refcount
	 */
	public_key_t* (*get_ref)(public_key_t *this);
	
	/**
	 * Destroy a public_key instance.
	 */
	void (*destroy)(public_key_t *this);
};

#endif /* PUBLIC_KEY_H_ @} */
