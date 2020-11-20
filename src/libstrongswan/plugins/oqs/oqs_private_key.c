/*
 * Copyright (C) 2020 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
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

#include "oqs_private_key.h"
#include "oqs_public_key.h"
#include "oqs_drbg.h"

#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <asn1/oid.h>
#include <crypto/rngs/rng_tester.h>

#include <oqs/oqs.h>

#define _GNU_SOURCE
#include <stdlib.h>

typedef struct private_oqs_private_key_t private_oqs_private_key_t;

/**
 * Private data of a oqs_private_key_t object.
 */
struct private_oqs_private_key_t {
	/**
	 * Public interface for this signer.
	 */
	oqs_private_key_t public;

	/**
	 * Key type
	 */
	key_type_t type;

	/**
	 * OID of the key type
	 */
	int oid;

	/**
	 * Internal OQS_SIG object
	 */
	OQS_SIG *sig;

	/**
	 * Public Key
	 */
	chunk_t public_key;

	/**
	 * Secret Key
	 */
	chunk_t secret_key;

	/**
	 * Deterministic Random Bit Generator (DRBG)
	 */
	drbg_t *drbg;

	/**
	 * reference count
	 */
	refcount_t ref;
};

METHOD(private_key_t, get_type, key_type_t,
	private_oqs_private_key_t *this)
{
	return this->type;
}


METHOD(private_key_t, sign, bool,
	private_oqs_private_key_t *this, signature_scheme_t scheme, void *params,
	chunk_t data, chunk_t *signature)
{
	if (key_type_from_signature_scheme(scheme) != this->type)
	{
		DBG1(DBG_LIB, "signature scheme %N not supported",
					   signature_scheme_names, scheme);
		return FALSE;
	}
	*signature = chunk_alloc(this->sig->length_signature);

	if (OQS_SIG_sign(this->sig, signature->ptr, &signature->len,
					 data.ptr, data.len, this->secret_key.ptr) != OQS_SUCCESS)
	{
		chunk_free(signature);
		return FALSE;
	}
	return TRUE;
}

METHOD(private_key_t, decrypt, bool,
	private_oqs_private_key_t *this, encryption_scheme_t scheme, void *params,
	chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "encryption scheme %N not supported",
				   encryption_scheme_names, scheme);
	return FALSE;
}

METHOD(private_key_t, get_keysize, int,
	private_oqs_private_key_t *this)
{
	return BITS_PER_BYTE * this->public_key.len;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_oqs_private_key_t *this)
{
	return lib->creds->create(lib->creds, CRED_PUBLIC_KEY, this->type,
							  BUILD_BLOB, this->public_key, BUILD_END);
}

METHOD(private_key_t, get_encoding, bool,
	private_oqs_private_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	switch (type)
	{
		case PRIVKEY_ASN1_DER:
		case PRIVKEY_PEM:
		{
			bool success = TRUE;
			chunk_t blob;

			blob = chunk_cat("cc", this->secret_key, this->public_key);

			*encoding = asn1_wrap(ASN1_SEQUENCE, "cms",
							ASN1_INTEGER_0,
							asn1_algorithmIdentifier(this->oid),
							asn1_wrap(ASN1_OCTET_STRING, "s",
								asn1_simple_object(ASN1_OCTET_STRING, blob)
							)
						);
			if (type == PRIVKEY_PEM)
			{
				chunk_t asn1_encoding = *encoding;

				success = lib->encoding->encode(lib->encoding, PRIVKEY_PEM,
								NULL, encoding, CRED_PART_PRIV_ASN1_DER,
								asn1_encoding, CRED_PART_END);
				chunk_clear(&asn1_encoding);
			}
			chunk_clear(&blob);

			return success;
		}
		default:
			return FALSE;
	}
}

METHOD(private_key_t, get_fingerprint, bool,
	private_oqs_private_key_t *this, cred_encoding_type_t type,
	chunk_t *fp)
{
	bool success;

	if (lib->encoding->get_cache(lib->encoding, type, this, fp))
	{
		return TRUE;
	}
	success = oqs_public_key_fingerprint(this->public_key, this->oid, type, fp);
	if (success)
	{
		lib->encoding->cache(lib->encoding, type, this, fp);
	}
	return success;
}

METHOD(private_key_t, get_ref, private_key_t*,
	private_oqs_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(private_key_t, destroy, void,
	private_oqs_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		DESTROY_IF(this->drbg);
		OQS_SIG_free(this->sig);
		chunk_clear(&this->secret_key);
		chunk_free(&this->public_key);
		free(this);
	}
}

/**
 * Internal generic constructor
 */
static private_oqs_private_key_t *oqs_private_key_create_empty(key_type_t type)
{
	private_oqs_private_key_t *this;
	char *sig_alg = NULL;
	OQS_SIG *sig;

	switch (type)
	{
		case KEY_DILITHIUM_2:
			sig_alg = OQS_SIG_alg_dilithium_2;
			break;
		case KEY_DILITHIUM_3:
			sig_alg = OQS_SIG_alg_dilithium_3;
			break;
		case KEY_DILITHIUM_5:
			sig_alg = OQS_SIG_alg_dilithium_5;
			break;
		case KEY_FALCON_512:
			sig_alg = OQS_SIG_alg_falcon_512;
			break;
		case KEY_FALCON_1024:
			sig_alg = OQS_SIG_alg_falcon_1024;
			break;
		default:
			return NULL;
	}

	if (OQS_randombytes_switch_algorithm(OQS_RAND_alg_openssl) != OQS_SUCCESS)
	{
		DBG1(DBG_LIB, "OQS RNG could not be switched to openssl");
		return NULL;
	}

	sig = OQS_SIG_new(sig_alg);
	if (!sig)
	{
		DBG1(DBG_LIB, "OQS '%s' signature algorithm not available", sig_alg);
		return NULL;
	}

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.sign = _sign,
				.decrypt = _decrypt,
				.get_keysize = _get_keysize,
				.get_public_key = _get_public_key,
				.equals = private_key_equals,
				.belongs_to = private_key_belongs_to,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = private_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.type = type,
		.oid = key_type_to_oid(type),
		.sig = sig,
		.secret_key = chunk_alloc(sig->length_secret_key),
		.public_key = chunk_alloc(sig->length_public_key),
		.ref = 1,
	);
	return this;
}

/**
 * See header.
 */
oqs_private_key_t *oqs_private_key_gen(key_type_t type, va_list args)
{
	private_oqs_private_key_t *this;
	drbg_t *drbg = NULL;

	if (!oqs_supported(type))
	{
		return NULL;
	}

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_KEY_SIZE:
				/* key_size argument is not needed */
				va_arg(args, u_int);
				continue;
			case BUILD_DRBG:
				drbg = va_arg(args, drbg_t*);
				continue;
		case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	this = oqs_private_key_create_empty(type);
	if (!this)
	{
		return NULL;
	}

	if (drbg)
	{
		this->drbg = drbg->get_ref(drbg);
		OQS_randombytes_custom_algorithm(oqs_drbg_rand);
		oqs_drbg_set(this->drbg);
	}

	if (OQS_SIG_keypair(this->sig, this->public_key.ptr,
								   this->secret_key.ptr) != OQS_SUCCESS)
	{
		DBG1(DBG_LIB, "OQS_SIG_keypair failed!");
		destroy(this);
		return NULL;
	}

	return &this->public;
}

/**
 * See header.
 */
oqs_private_key_t *oqs_private_key_load(key_type_t type, va_list args)
{
	private_oqs_private_key_t *this;
	chunk_t blob = chunk_empty;

	if (!oqs_supported(type))
	{
		return NULL;
	}

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_PRIV_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (!asn1_parse_simple_object(&blob, ASN1_OCTET_STRING, 0, "PrivateKey"))
	{
		return NULL;
	}

	this = oqs_private_key_create_empty(type);
	if (!this)
	{
		return NULL;
	}

	/* Dilithium private keys contain the public key */
	if (blob.len != this->sig->length_public_key + this->sig->length_secret_key)
	{
		return NULL;
	}
	memcpy(this->secret_key.ptr, blob.ptr, this->secret_key.len);
	blob = chunk_skip(blob, this->secret_key.len);
	memcpy(this->public_key.ptr, blob.ptr, this->public_key.len);

	return &this->public;
}
