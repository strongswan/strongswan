/*
 * Copyright (C) 2009 Martin Willi
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

#include "openssl_ec_private_key.h"
#include "openssl_ec_public_key.h"
#include "openssl_util.h"

#include <debug.h>

#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>

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
	{SIGN_ECDSA_WITH_SHA1,	NID_sha1,	-1},
	{SIGN_ECDSA_256,		NID_sha256,	NID_X9_62_prime256v1},
	{SIGN_ECDSA_384,		NID_sha384,	NID_secp384r1},
	{SIGN_ECDSA_521,		NID_sha512,	NID_secp521r1},
	{END_OF_LIST,			0,			0},
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

/* from ec public key */
bool openssl_ec_fingerprint(EC_KEY *ec, key_encoding_type_t type, chunk_t *fp);

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
							chunk_t hash, chunk_t *signature)
{
	ECDSA_SIG *sig;
	bool success;
	
	sig = ECDSA_do_sign(hash.ptr, hash.len, this->ec);
	if (!sig)
	{
		return FALSE;
	}
	success = sig2chunk(EC_KEY_get0_group(this->ec), sig, signature);
	ECDSA_SIG_free(sig);
	return success;
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
	bool success;
	
	if (scheme == SIGN_ECDSA_WITH_NULL)
	{
		success = build_signature(this, data, signature);
	}
	else
	{
		EC_GROUP *req_group;
		const EC_GROUP *my_group;
		chunk_t hash = chunk_empty;
		int hash_type, curve;
		
		if (!lookup_scheme(scheme, &hash_type, &curve))
		{
			DBG1("signature scheme %N not supported in EC",
					 signature_scheme_names, scheme);
			return FALSE;
		}
		
		if (curve != -1)
		{
			req_group = EC_GROUP_new_by_curve_name(curve);
			if (!req_group)
			{
				DBG1("signature scheme %N not supported in EC (required curve "
					 "not supported)", signature_scheme_names, scheme);
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
		}
		if (!openssl_hash_chunk(hash_type, data, &hash))
		{
			return FALSE;
		}
		success = build_signature(this, hash, signature);
		chunk_free(&hash);
	}	
	return success;
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
 * Implementation of private_key_t.get_public_key.
 */
static public_key_t* get_public_key(private_openssl_ec_private_key_t *this)
{
	public_key_t *public;
	chunk_t key;
	u_char *p;
	
	key = chunk_alloc(i2d_EC_PUBKEY(this->ec, NULL));
	p = key.ptr;
	i2d_EC_PUBKEY(this->ec, &p);
	
	public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ECDSA,
								BUILD_BLOB_ASN1_DER, key, BUILD_END);
	free(key.ptr);
	return public;
}

/**
 * Implementation of private_key_t.get_fingerprint.
 */
static bool get_fingerprint(private_openssl_ec_private_key_t *this,
							key_encoding_type_t type, chunk_t *fingerprint)
{
	return openssl_ec_fingerprint(this->ec, type, fingerprint);
}

/**
 * Implementation of private_key_t.get_encoding.
 */
static bool get_encoding(private_openssl_ec_private_key_t *this,
						 key_encoding_type_t type, chunk_t *encoding)
{
	u_char *p;
	
	switch (type)
	{
		case KEY_PRIV_ASN1_DER:
		{
			*encoding = chunk_alloc(i2d_ECPrivateKey(this->ec, NULL));
			p = encoding->ptr;
			i2d_ECPrivateKey(this->ec, &p);
			return TRUE;
		}
		default:
			return FALSE;
	}
}

/**
 * Implementation of private_key_t.get_ref.
 */
static private_key_t* get_ref(private_openssl_ec_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.interface;
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
			lib->encoding->clear_cache(lib->encoding, this->ec);
			EC_KEY_free(this->ec);
		}
		free(this);
	}
}

/**
 * Internal generic constructor
 */
static private_openssl_ec_private_key_t *create_empty(void)
{
	private_openssl_ec_private_key_t *this = malloc_thing(private_openssl_ec_private_key_t);
	
	this->public.interface.get_type = (key_type_t (*)(private_key_t *this))get_type;
	this->public.interface.sign = (bool (*)(private_key_t *this, signature_scheme_t scheme, chunk_t data, chunk_t *signature))sign;
	this->public.interface.decrypt = (bool (*)(private_key_t *this, chunk_t crypto, chunk_t *plain))decrypt;
	this->public.interface.get_keysize = (size_t (*) (private_key_t *this))get_keysize;
	this->public.interface.get_public_key = (public_key_t* (*)(private_key_t *this))get_public_key;
	this->public.interface.equals = private_key_equals;
	this->public.interface.belongs_to = private_key_belongs_to;
	this->public.interface.get_fingerprint = (bool(*)(private_key_t*, key_encoding_type_t type, chunk_t *fp))get_fingerprint;
	this->public.interface.get_encoding = (bool(*)(private_key_t*, key_encoding_type_t type, chunk_t *encoding))get_encoding;
	this->public.interface.get_ref = (private_key_t* (*)(private_key_t *this))get_ref;
	this->public.interface.destroy = (void (*)(private_key_t *this))destroy;
	
	this->ec = NULL;
	this->ref = 1;
	
	return this;
}

/**
 * Generate an ECDSA key of specified key size
 */
static openssl_ec_private_key_t *generate(size_t key_size)
{
	private_openssl_ec_private_key_t *this = create_empty();
	
	switch (key_size)
	{
		case 256:
			this->ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
			break;
		case 384:
			this->ec = EC_KEY_new_by_curve_name(NID_secp384r1);
			break;
		case 521:
			this->ec = EC_KEY_new_by_curve_name(NID_secp521r1);
			break;
		default:
			DBG1("EC private key size %d not supported", key_size);
			destroy(this);
			return NULL;
	}
	if (EC_KEY_generate_key(this->ec) != 1)
	{
		DBG1("EC private key generation failed", key_size);
		destroy(this);
		return NULL;
	}
	/* encode as a named curve key (no parameters), uncompressed public key */
	EC_KEY_set_asn1_flag(this->ec, OPENSSL_EC_NAMED_CURVE);
	EC_KEY_set_conv_form(this->ec, POINT_CONVERSION_UNCOMPRESSED);
	return &this->public;
}

/**
 * load private key from an ASN1 encoded blob
 */
static openssl_ec_private_key_t *load(chunk_t blob)
{
	private_openssl_ec_private_key_t *this = create_empty();
	
	this->ec = d2i_ECPrivateKey(NULL, (const u_char**)&blob.ptr, blob.len);
	
	if (!this->ec)
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
	if (!this->key)
	{
		va_list args;
		
		switch (part)
		{
			case BUILD_KEY_SIZE:
			{
				va_start(args, part);
				this->key = generate(va_arg(args, u_int));
				va_end(args);
				return;
			}
			case BUILD_BLOB_ASN1_DER:
			{
				va_start(args, part);
				this->key = load(va_arg(args, chunk_t));
				va_end(args);
				return;
			}
			default:
				break;
		}
	}
	if (this->key)
	{
		destroy((private_openssl_ec_private_key_t*)this->key);
	}
	builder_cancel(&this->public);
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

