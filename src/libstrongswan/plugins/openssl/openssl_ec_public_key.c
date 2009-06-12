/*
 * Copyright (C) 2008 Tobias Brunner
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

#include "openssl_ec_public_key.h"
#include "openssl_util.h"

#include <debug.h>

#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>

typedef struct private_openssl_ec_public_key_t private_openssl_ec_public_key_t;

/**
 * Private data structure with signing context.
 */
struct private_openssl_ec_public_key_t {
	/**
	 * Public interface for this signer.
	 */
	openssl_ec_public_key_t public;
	
	/**
	 * EC key object
	 */
	EC_KEY *ec;
	
	/**
	 * Keyid formed as a SHA-1 hash of a publicKeyInfo object
	 */
	identification_t *keyid_info;
	
	/**
	 * Keyid formed as a SHA-1 hash of a publicKey object
	 */
	identification_t *keyid;
	
	/**
	 * reference counter
	 */
	refcount_t ref;
};

/**
 * Convert a chunk to an ECDSA_SIG (which must already exist). r and s
 * of the signature have to be concatenated in the chunk.
 */
static bool chunk2sig(const EC_GROUP *group, chunk_t chunk, ECDSA_SIG *sig)
{
	return openssl_bn_split(chunk, sig->r, sig->s);
}

/**
 * Verification of a signature as in RFC 4754
 */
static bool verify_signature(private_openssl_ec_public_key_t *this,
								int hash_type, chunk_t data, chunk_t signature)
{
	chunk_t hash = chunk_empty;
	ECDSA_SIG *sig;
	bool valid = FALSE;
	
	if (hash_type == NID_undef)
	{
		hash = data;
	}
	else
	{
		if (!openssl_hash_chunk(hash_type, data, &hash))
		{
			return FALSE;
		}
	}
	
	sig = ECDSA_SIG_new();
	if (!sig)
	{
		goto error;
	}
	
	if (!chunk2sig(EC_KEY_get0_group(this->ec), signature, sig))
	{
		goto error;
	}
	valid = (ECDSA_do_verify(hash.ptr, hash.len, sig, this->ec) == 1);
	
error:
	if (sig)
	{
		ECDSA_SIG_free(sig);
	}
	if (hash_type != NID_undef)
	{
		chunk_free(&hash);
	}
	return valid;
}


/**
 * Verification of the default signature using SHA-1
 */
static bool verify_default_signature(private_openssl_ec_public_key_t *this,
								chunk_t data, chunk_t signature)
{
	bool valid = FALSE;
	chunk_t hash = chunk_empty;
	u_char *p;
	ECDSA_SIG *sig;
	
	/* remove any preceding 0-bytes from signature */
	while (signature.len && *(signature.ptr) == 0x00)
	{
		signature.len -= 1;
		signature.ptr++;
	}
	
	p = signature.ptr;
	sig = d2i_ECDSA_SIG(NULL, (const u_char**)&p, signature.len);
	if (!sig)
	{
		return FALSE;
	}
	
	if (!openssl_hash_chunk(NID_sha1, data, &hash))
	{
		goto error;
	}
	
	valid = (ECDSA_do_verify(hash.ptr, hash.len, sig, this->ec) == 1);

error:
	if (sig)
	{
		ECDSA_SIG_free(sig);
	}
	chunk_free(&hash);
	return valid;
}

/**
 * Implementation of public_key_t.get_type.
 */
static key_type_t get_type(private_openssl_ec_public_key_t *this)
{
	return KEY_ECDSA;
}

/**
 * Implementation of public_key_t.verify.
 */
static bool verify(private_openssl_ec_public_key_t *this, signature_scheme_t scheme, 
				   chunk_t data, chunk_t signature)
{
	switch (scheme)
	{
		case SIGN_ECDSA_WITH_NULL:
			return verify_signature(this, NID_undef, data, signature);
		case SIGN_ECDSA_WITH_SHA1:
			return verify_default_signature(this, data, signature);
		case SIGN_ECDSA_256:
			return verify_signature(this, NID_sha256, data, signature);
		case SIGN_ECDSA_384:
			return verify_signature(this, NID_sha384, data, signature);
		case SIGN_ECDSA_521:
			return verify_signature(this, NID_sha512, data, signature);
		default:
			DBG1("signature scheme %N not supported in EC",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

/**
 * Implementation of public_key_t.get_keysize.
 */
static bool encrypt_(private_openssl_ec_public_key_t *this, chunk_t crypto, chunk_t *plain)
{
	DBG1("EC public key encryption not implemented");
	return FALSE;
}

/**
 * Implementation of public_key_t.get_keysize.
 */
static size_t get_keysize(private_openssl_ec_public_key_t *this)
{
	return EC_FIELD_ELEMENT_LEN(EC_KEY_get0_group(this->ec));
}

/**
 * Implementation of public_key_t.get_id.
 */
static identification_t *get_id(private_openssl_ec_public_key_t *this,
								id_type_t type)
{
	switch (type)
	{
		case ID_PUBKEY_INFO_SHA1:
			return this->keyid_info;
		case ID_PUBKEY_SHA1:
			return this->keyid;
		default:
			return NULL;
	}
}

/**
 * Encodes the public key
 */ 
static chunk_t get_encoding_raw(EC_KEY *ec)
{
	/* since the points can be stored in three different forms this may not
	 * be correct for all cases */
	const EC_GROUP *group = EC_KEY_get0_group(ec);
	const EC_POINT *pub = EC_KEY_get0_public_key(ec);
	chunk_t enc = chunk_alloc(EC_POINT_point2oct(group, pub,
						POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL));
	EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
						enc.ptr, enc.len, NULL);
	return enc;	
}

/**
 * Encodes the public key info (public key with ec parameters)
 */ 
static chunk_t get_encoding_full(EC_KEY *ec)
{
	chunk_t enc = chunk_alloc(i2d_EC_PUBKEY(ec, NULL));
	u_char *p = enc.ptr;
	i2d_EC_PUBKEY(ec, &p);
	return enc;
}

/*
 * Implementation of public_key_t.get_encoding.
 */
static chunk_t get_encoding(private_openssl_ec_public_key_t *this)
{
	return get_encoding_full(this->ec);
}

/**
 * Implementation of public_key_t.get_ref.
 */
static private_openssl_ec_public_key_t* get_ref(private_openssl_ec_public_key_t *this)
{
	ref_get(&this->ref);
	return this;
}

/**
 * Implementation of openssl_ec_public_key.destroy.
 */
static void destroy(private_openssl_ec_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		if (this->ec)
		{
			EC_KEY_free(this->ec);
		}
		DESTROY_IF(this->keyid);
		DESTROY_IF(this->keyid_info);
		free(this);
	}
}

/**
 * Generic private constructor
 */
static private_openssl_ec_public_key_t *openssl_ec_public_key_create_empty()
{
	private_openssl_ec_public_key_t *this = malloc_thing(private_openssl_ec_public_key_t);
	
	this->public.interface.get_type = (key_type_t (*)(public_key_t *this))get_type;
	this->public.interface.verify = (bool (*)(public_key_t *this, signature_scheme_t scheme, chunk_t data, chunk_t signature))verify;
	this->public.interface.encrypt = (bool (*)(public_key_t *this, chunk_t crypto, chunk_t *plain))encrypt_;
	this->public.interface.get_keysize = (size_t (*) (public_key_t *this))get_keysize;
	this->public.interface.get_id = (identification_t* (*) (public_key_t *this,id_type_t))get_id;
	this->public.interface.get_encoding = (chunk_t(*)(public_key_t*))get_encoding;
	this->public.interface.get_ref = (public_key_t* (*)(public_key_t *this))get_ref;
	this->public.interface.destroy = (void (*)(public_key_t *this))destroy;
	
	this->ec = NULL;
	this->keyid = NULL;
	this->keyid_info = NULL;
	this->ref = 1;
	
	return this;
}

/**
 * Build key identifier from the public key using SHA1 hashed publicKey(Info).
 * Also used in openssl_ec_private_key.c.
 */
bool openssl_ec_public_key_build_id(EC_KEY *ec, identification_t **keyid,
								 identification_t **keyid_info)
{
	chunk_t publicKeyInfo, publicKey, hash;
	hasher_t *hasher;
	
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (hasher == NULL)
	{
		DBG1("SHA1 hash algorithm not supported, unable to use EC");
		return FALSE;
	}
	
	publicKey = get_encoding_raw(ec);
	
	hasher->allocate_hash(hasher, publicKey, &hash);
	*keyid = identification_create_from_encoding(ID_PUBKEY_SHA1, hash);
	chunk_free(&hash);
	
	publicKeyInfo = get_encoding_full(ec);
	
	hasher->allocate_hash(hasher, publicKeyInfo, &hash);
	*keyid_info = identification_create_from_encoding(ID_PUBKEY_INFO_SHA1, hash);
	chunk_free(&hash);
	
	hasher->destroy(hasher);
	chunk_free(&publicKeyInfo);
	chunk_free(&publicKey);
	
	return TRUE;
}

/**
 * Load a public key from an ASN1 encoded blob
 */
static openssl_ec_public_key_t *load(chunk_t blob)
{
	u_char *p = blob.ptr;
	private_openssl_ec_public_key_t *this = openssl_ec_public_key_create_empty();
	
	this->ec = d2i_EC_PUBKEY(NULL, (const u_char**)&p, blob.len);
	
	chunk_clear(&blob);
	
	if (!this->ec)
	{
		destroy(this);
		return NULL;
	}
	
	if (!openssl_ec_public_key_build_id(this->ec, &this->keyid, &this->keyid_info))
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

/**
 * Create a public key from BIGNUM values, used in openssl_ec_private_key.c
 */
openssl_ec_public_key_t *openssl_ec_public_key_create_from_private_key(EC_KEY *ec)
{
	return (openssl_ec_public_key_t*)load(get_encoding_full(ec));
}

typedef struct private_builder_t private_builder_t;
/**
 * Builder implementation for key loading
 */
struct private_builder_t {
	/** implements the builder interface */
	builder_t public;
	/** loaded public key */
	openssl_ec_public_key_t *key;
};

/**
 * Implementation of builder_t.build
 */
static openssl_ec_public_key_t *build(private_builder_t *this)
{
	openssl_ec_public_key_t *key = this->key;
	
	free(this);
	return key;
}

/**
 * Implementation of builder_t.add
 */
static void add(private_builder_t *this, builder_part_t part, ...)
{
	if (!this->key)
	{
		va_list args;
		chunk_t chunk;
	
		switch (part)
		{
			case BUILD_BLOB_ASN1_DER:
			{
				va_start(args, part);
				chunk = va_arg(args, chunk_t);
				this->key = load(chunk_clone(chunk));
				va_end(args);
				return;
			}
			default:
				break;
		}
	}
	if (this->key)
	{
		destroy((private_openssl_ec_public_key_t*)this->key);
	}
	builder_cancel(&this->public);
}

/**
 * Builder construction function
 */
builder_t *openssl_ec_public_key_builder(key_type_t type)
{
	private_builder_t *this;
	
	if (type != KEY_ECDSA)
	{
		return NULL;
	}
	
	this = malloc_thing(private_builder_t);
	
	this->key = NULL;
	this->public.add = (void(*)(builder_t *this, builder_part_t part, ...))add;
	this->public.build = (void*(*)(builder_t *this))build;
	
	return &this->public;
}

