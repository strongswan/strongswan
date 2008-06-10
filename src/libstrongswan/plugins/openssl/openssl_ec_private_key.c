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
 *
 * $Id$
 */

#include "openssl_ec_private_key.h"
#include "openssl_ec_public_key.h"
#include "openssl_util.h"

#include <debug.h>

#include <openssl/evp.h>
#include <openssl/ecdsa.h>

typedef struct private_openssl_ec_private_key_t private_openssl_ec_private_key_t;

/**
 * Private data of a openssl_ec_private_key_t object.
 */
struct private_openssl_ec_private_key_t {
	/**
	 * Public interface for this signer.
	 */
	openssl_ec_private_key_t public;
	
	/**
	 * EC key object
	 */
	EC_KEY *ec;

	/**
	 * Keyid formed as a SHA-1 hash of a privateKey object
	 */
	identification_t* keyid;

	/**
	 * Keyid formed as a SHA-1 hash of a privateKeyInfo object
	 */
	identification_t* keyid_info;
	
	/**
	 * reference count
	 */
	refcount_t ref;	
};

/**
 * Mapping from the signature scheme defined in (RFC 4754) to the elliptic
 * curve and the hash algorithm
 */
typedef struct {
	/**
	 * Scheme specified in RFC 4754
	 */
	int scheme;
	
	/**
	 * NID of the hash
	 */
	int hash;
	
	/**
	 * NID of the curve
	 */
	int curve;
} openssl_ecdsa_scheme_t;

#define END_OF_LIST -1

/**
 * Signature schemes
 */
static openssl_ecdsa_scheme_t ecdsa_schemes[] = {
	{SIGN_ECDSA_256, NID_sha256, NID_X9_62_prime256v1},
	{SIGN_ECDSA_384, NID_sha384, NID_secp384r1},
	{SIGN_ECDSA_521, NID_sha512, NID_secp521r1},
	{END_OF_LIST,    0,          0},
};

/**
 * Look up the hash and curve of a signature scheme
 */
static bool lookup_scheme(int scheme, int *hash, int *curve)
{
	openssl_ecdsa_scheme_t *ecdsa_scheme = ecdsa_schemes;
	while (ecdsa_scheme->scheme != END_OF_LIST)
	{
		if (scheme == ecdsa_scheme->scheme)
		{
			*hash = ecdsa_scheme->hash;
			*curve = ecdsa_scheme->curve;
			return TRUE;
		}
		ecdsa_scheme++;
	}
	return FALSE;
}

/**
 * shared functions, implemented in openssl_ec_public_key.c
 */
bool openssl_ec_public_key_build_id(EC_KEY *ec, identification_t **keyid,
								 identification_t **keyid_info);

openssl_ec_public_key_t *openssl_ec_public_key_create_from_private_key(EC_KEY *ec);


/**
 * Convert an ECDSA_SIG to a chunk by concatenating r and s.
 * This function allocates memory for the chunk.
 */
static bool sig2chunk(const EC_GROUP *group, ECDSA_SIG *sig, chunk_t *chunk)
{
	return openssl_bn_cat(EC_FIELD_ELEMENT_LEN(group), sig->r, sig->s, chunk);
}

/**
 * Build the signature
 */
static bool build_signature(private_openssl_ec_private_key_t *this,
							int hash_type, chunk_t data, chunk_t *signature)
{
	chunk_t hash = chunk_empty;
	ECDSA_SIG *sig;
	bool ret = FALSE;
	
	if (!openssl_hash_chunk(hash_type, data, &hash))
	{
		return FALSE;
	}
	
	sig = ECDSA_do_sign(hash.ptr, hash.len, this->ec);
	if (!sig)
	{
		goto error;
	}
	
	if (!sig2chunk(EC_KEY_get0_group(this->ec), sig, signature))
	{
		goto error;
	}
	
	ret = TRUE;
error:
	chunk_free(&hash);
	if (sig)
	{
		ECDSA_SIG_free(sig);
	}
	return ret;
}

/**
 * Implementation of private_key_t.get_type.
 */
static key_type_t get_type(private_openssl_ec_private_key_t *this)
{
	return KEY_ECDSA;
}

/**
 * Implementation of private_key_t.sign.
 */
static bool sign(private_openssl_ec_private_key_t *this, signature_scheme_t scheme, 
				 chunk_t data, chunk_t *signature)
{
	EC_GROUP *req_group;
	const EC_GROUP *my_group;
	int hash, curve;
	
	if (!lookup_scheme(scheme, &hash, &curve))
	{
		DBG1("signature scheme %N not supported in EC",
				 signature_scheme_names, scheme);
		return FALSE;
	}
	
	req_group = EC_GROUP_new_by_curve_name(curve);
	if (!req_group)
	{
		DBG1("signature scheme %N not supported in EC (required curve not supported)",
				 signature_scheme_names, scheme);
		return FALSE;
	}
	
	my_group = EC_KEY_get0_group(this->ec);
	if (EC_GROUP_cmp(my_group, req_group, NULL) != 0)
	{
		DBG1("signature scheme %N not supported by private key",
				 signature_scheme_names, scheme);
		return FALSE;
	}
	
	EC_GROUP_free(req_group);
	
	return build_signature(this, hash, data, signature);
}

/**
 * Implementation of private_key_t.destroy.
 */
static bool decrypt(private_openssl_ec_private_key_t *this,
					chunk_t crypto, chunk_t *plain)
{
	DBG1("EC private key decryption not implemented");
	return FALSE;
}

/**
 * Implementation of private_key_t.get_keysize.
 */
static size_t get_keysize(private_openssl_ec_private_key_t *this)
{
	return EC_FIELD_ELEMENT_LEN(EC_KEY_get0_group(this->ec));
}

/**
 * Implementation of private_key_t.get_id.
 */
static identification_t* get_id(private_openssl_ec_private_key_t *this,
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
 * Implementation of private_key_t.get_public_key.
 */
static openssl_ec_public_key_t* get_public_key(private_openssl_ec_private_key_t *this)
{
	return openssl_ec_public_key_create_from_private_key(this->ec);
}

/**
 * Implementation of private_key_t.belongs_to.
 */
static bool belongs_to(private_openssl_ec_private_key_t *this, public_key_t *public)
{
	identification_t *keyid;

	if (public->get_type(public) != KEY_ECDSA)
	{
		return FALSE;
	}
	keyid = public->get_id(public, ID_PUBKEY_SHA1);
	if (keyid && keyid->equals(keyid, this->keyid))
	{
		return TRUE;
	}
	keyid = public->get_id(public, ID_PUBKEY_INFO_SHA1);
	if (keyid && keyid->equals(keyid, this->keyid_info))
	{
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of private_key_t.get_encoding.
 */
static chunk_t get_encoding(private_openssl_ec_private_key_t *this)
{
	chunk_t enc = chunk_alloc(i2d_ECPrivateKey(this->ec, NULL));
	u_char *p = enc.ptr;
	i2d_ECPrivateKey(this->ec, &p);
	return enc;
}

/**
 * Implementation of private_key_t.get_ref.
 */
static private_openssl_ec_private_key_t* get_ref(private_openssl_ec_private_key_t *this)
{
	ref_get(&this->ref);
	return this;

}

/**
 * Implementation of private_key_t.destroy.
 */
static void destroy(private_openssl_ec_private_key_t *this)
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
 * Internal generic constructor
 */
static private_openssl_ec_private_key_t *openssl_ec_private_key_create_empty(void)
{
	private_openssl_ec_private_key_t *this = malloc_thing(private_openssl_ec_private_key_t);
	
	this->public.interface.get_type = (key_type_t (*)(private_key_t *this))get_type;
	this->public.interface.sign = (bool (*)(private_key_t *this, signature_scheme_t scheme, chunk_t data, chunk_t *signature))sign;
	this->public.interface.decrypt = (bool (*)(private_key_t *this, chunk_t crypto, chunk_t *plain))decrypt;
	this->public.interface.get_keysize = (size_t (*) (private_key_t *this))get_keysize;
	this->public.interface.get_id = (identification_t* (*) (private_key_t *this,id_type_t))get_id;
	this->public.interface.get_public_key = (public_key_t* (*)(private_key_t *this))get_public_key;
	this->public.interface.belongs_to = (bool (*) (private_key_t *this, public_key_t *public))belongs_to;
	this->public.interface.get_encoding = (chunk_t(*)(private_key_t*))get_encoding;
	this->public.interface.get_ref = (private_key_t* (*)(private_key_t *this))get_ref;
	this->public.interface.destroy = (void (*)(private_key_t *this))destroy;
	
	this->ec = NULL;
	this->keyid = NULL;
	this->keyid_info = NULL;
	this->ref = 1;
	
	return this;
}

/**
 * load private key from an ASN1 encoded blob
 */
static openssl_ec_private_key_t *load(chunk_t blob)
{
	u_char *p = blob.ptr;
	private_openssl_ec_private_key_t *this = openssl_ec_private_key_create_empty();
	
	this->ec = d2i_ECPrivateKey(NULL, (const u_char**)&p, blob.len);
	
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
	
	if (!EC_KEY_check_key(this->ec))
	{
		destroy(this);
		return NULL;
	}
	
	return &this->public;
}

typedef struct private_builder_t private_builder_t;
/**
 * Builder implementation for key loading/generation
 */
struct private_builder_t {
	/** implements the builder interface */
	builder_t public;
	/** loaded/generated private key */
	openssl_ec_private_key_t *key;
};

/**
 * Implementation of builder_t.build
 */
static openssl_ec_private_key_t *build(private_builder_t *this)
{
	openssl_ec_private_key_t *key = this->key;
	
	free(this);
	return key;
}

/**
 * Implementation of builder_t.add
 */
static void add(private_builder_t *this, builder_part_t part, ...)
{
	va_list args;
	
	if (this->key)
	{
		DBG1("ignoring surplus build part %N", builder_part_names, part);
		return;
	}
	
	switch (part)
	{
		case BUILD_BLOB_ASN1_DER:
		{
			va_start(args, part);
			this->key = load(va_arg(args, chunk_t));
			va_end(args);
			break;
		}
		default:
			DBG1("ignoring unsupported build part %N", builder_part_names, part);
			break;
	}
}

/**
 * Builder construction function
 */
builder_t *openssl_ec_private_key_builder(key_type_t type)
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

