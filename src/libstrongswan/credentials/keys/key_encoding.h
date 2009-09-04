/*
 * Copyright (C) 2009 Martin Willi
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
 * @defgroup key_encoding key_encoding
 * @{ @ingroup keys
 */

#ifndef KEY_ENCODING_H_
#define KEY_ENCODING_H_

typedef struct key_encoding_t key_encoding_t;
typedef enum key_encoding_type_t key_encoding_type_t;
typedef enum key_encoding_part_t key_encoding_part_t;

#include <library.h>

/**
 * Key encoder function implementing encoding/fingerprinting.
 *
 * The variable argument list takes key_encoding_part_t, followed by part
 * specific arguments, terminated by KEY_PART_END.
 *
 * @param type		format to encode the key to
 * @param args		list of (key_encoding_part_t, data)
 * @param encoding	encoding result, allocated
 * @return			TRUE if encoding successful
 */
typedef bool (*key_encoder_t)(key_encoding_type_t type, chunk_t *encoding,
							  va_list args);

/**
 * Helper function for key_encoder_t implementations to parse argument list.
 *
 * Key encoder functions get a variable argument list to parse. To simplify
 * the job, this function reads the arguments and returns chunks for each
 * part.
 * The argument list of this function takes a key_encoding_part_t, followed
 * by a data pointer receiving the value, terminated by KEY_PART_END.
 *
 * @param args		argument list passed to key encoder function
 * @param ...		list of (key_encoding_part_t, data*)
 * @return			TRUE if all parts found, FALSE otherwise
 */
bool key_encoding_args(va_list args, ...);

/**
 * Encoding type of a fingerprint/private-/public-key.
 *
 * Fingerprints have have the KEY_ID_*, public keys the KEY_PUB_* and
 * private keys the KEY_PRIV_* prefix.
 */
enum key_encoding_type_t {
	/** SHA1 fingerprint over subjectPublicKeyInfo */
	KEY_ID_PUBKEY_INFO_SHA1 = 0,
	/** SHA1 fingerprint over subjectPublicKey */
	KEY_ID_PUBKEY_SHA1,
	/** PGPv3 fingerprint */
	KEY_ID_PGPV3,
	/** PGPv4 fingerprint */
	KEY_ID_PGPV4,

	/** PKCS#1 and similar ASN.1 key encoding */
	KEY_PUB_ASN1_DER,
	KEY_PRIV_ASN1_DER,
	/** subjectPublicKeyInfo encoding */
	KEY_PUB_SPKI_ASN1_DER,
	/** PEM oncoded PKCS#1 key */
	KEY_PUB_PEM,
	KEY_PRIV_PEM,
	/** PGP key encoding */
	KEY_PUB_PGP,
	KEY_PRIV_PGP,

	KEY_ENCODING_MAX,
};

/**
 * Parts of a key to encode.
 */
enum key_encoding_part_t {
	/** modulus of a RSA key, n */
	KEY_PART_RSA_MODULUS,
	/** public exponent of a RSA key, e */
	KEY_PART_RSA_PUB_EXP,
	/** private exponent of a RSA key, d */
	KEY_PART_RSA_PRIV_EXP,
	/** prime1 a RSA key, p */
	KEY_PART_RSA_PRIME1,
	/** prime2 a RSA key, q */
	KEY_PART_RSA_PRIME2,
	/** exponent1 a RSA key, exp1 */
	KEY_PART_RSA_EXP1,
	/** exponent1 a RSA key, exp2 */
	KEY_PART_RSA_EXP2,
	/** coefficient of RSA key, coeff */
	KEY_PART_RSA_COEFF,
	/** a DER encoded RSA public key */
	KEY_PART_RSA_PUB_ASN1_DER,
	/** a DER encoded RSA private key */
	KEY_PART_RSA_PRIV_ASN1_DER,
	/** a DER encoded ECDSA public key */
	KEY_PART_ECDSA_PUB_ASN1_DER,
	/** a DER encoded ECDSA private key */
	KEY_PART_ECDSA_PRIV_ASN1_DER,

	KEY_PART_END,
};

/**
 * Private/Public key encoding and fingerprinting facility.
 */
struct key_encoding_t {

	/**
	 * Encode a key into a format using several key parts, optional caching.
	 *
	 * The variable argument list takes key_encoding_part_t, followed by part
	 * specific arguments, terminated by KEY_PART_END.
	 * If a cache key is given, the returned encoding points to internal data:
	 * do not free or modify. If no cache key is given, the encoding is
	 * allocated and must be freed by the caller.
	 *
	 * @param type			format the key should be encoded to
	 * @param cache			key to use for caching, NULL to not cache
	 * @param encoding		encoding result, allocated if caching disabled
	 * @param ...			list of (key_encoding_part_t, data)
	 * @return				TRUE if encoding successful
	 */
	bool (*encode)(key_encoding_t *this, key_encoding_type_t type, void *cache,
				   chunk_t *encoding, ...);

	/**
	 * Clear all cached encodings of a given cache key.
	 *
	 * @param cache			key used in encode() for caching
	 */
	void (*clear_cache)(key_encoding_t *this, void *cache);

	/**
	 * Check for a cached encoding.
	 *
	 * @param type			format of the key encoding
	 * @param cache			key to use for caching, as given to encode()
	 * @param encoding		encoding result, internal data
	 * @return				TRUE if cache entry found
	 */
	bool (*get_cache)(key_encoding_t *this, key_encoding_type_t type,
					  void *cache, chunk_t *encoding);

	/**
	 * Cache a key encoding created externally.
	 *
	 * After calling cache(), the passed encoding is owned by the key encoding
	 * facility.
	 *
	 * @param type			format of the key encoding
	 * @param cache			key to use for caching, as given to encode()
	 * @param encoding		encoding to cache, gets owned by this
	 */
	void (*cache)(key_encoding_t *this, key_encoding_type_t type, void *cache,
				  chunk_t encoding);

	/**
	 * Register a key encoder function.
	 *
	 * @param encoder		key encoder function to add
	 */
	void (*add_encoder)(key_encoding_t *this, key_encoder_t encoder);

	/**
	 * Unregister a previously registered key encoder function.
	 *
	 * @param encoder		key encoder function to remove
	 */
	void (*remove_encoder)(key_encoding_t *this, key_encoder_t encoder);

	/**
	 * Destroy a key_encoding_t.
	 */
	void (*destroy)(key_encoding_t *this);
};

/**
 * Create a key_encoding instance.
 */
key_encoding_t *key_encoding_create();

#endif /* KEY_ENCODING_ @}*/
