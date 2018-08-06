/*
 * Copyright (C) 2018 René Korthaus
 * Copyright (C) 2018 Konstantinos Kolelis
 * Rohde & Schwarz Cybersecurity GmbH
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#include "botan_ec_private_key.h"
#include "botan_util.h"

#include <botan/build.h>

#ifdef BOTAN_HAS_ECDSA

#include <asn1/asn1.h>
#include <asn1/oid.h>
#include <asn1/asn1_parser.h>

#include <utils/debug.h>

#include <botan/ffi.h>

typedef struct private_botan_ec_private_key_t private_botan_ec_private_key_t;

/**
 * Private data of a botan_ec_private_key_t object.
 */
struct private_botan_ec_private_key_t {

	/**
	 * Public interface
	 */
	botan_ec_private_key_t public;

	/**
	 * Botan ec private key
	 */
	botan_privkey_t key;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

#define SIG_FORMAT_IEEE_1363 0
#define SIG_FORMAT_DER_SEQUENCE 1

/**
 * Build a DER encoded signature as in RFC 3279 or as in RFC 4754
 */
static bool build_signature(botan_privkey_t key, const char *hash_and_padding,
							int signature_format, chunk_t data,
							chunk_t *signature)
{
	if (!botan_get_signature(key, hash_and_padding, data, signature))
	{
		return FALSE;
	}

	if (signature_format == SIG_FORMAT_DER_SEQUENCE)
	{
		/* format as ASN.1 sequence of two integers r,s */
		chunk_t r = chunk_empty, s = chunk_empty;

		chunk_split(*signature, "aa", signature->len / 2, &r,
					signature->len / 2, &s);

		chunk_free(signature);
		*signature = asn1_wrap(ASN1_SEQUENCE, "mm", asn1_integer("m", r),
							   asn1_integer("m", s));
	}
	return TRUE;
}

METHOD(private_key_t, sign, bool,
	private_botan_ec_private_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t *signature)
{
	switch (scheme)
	{
		/* r||s -> Botan::IEEE_1363, data is the hash already */
		case SIGN_ECDSA_WITH_NULL:
			return build_signature(this->key, "Raw",
								   SIG_FORMAT_IEEE_1363, data, signature);
		/* DER SEQUENCE of two INTEGERS r,s -> Botan::DER_SEQUENCE */
		case SIGN_ECDSA_WITH_SHA1_DER:
			return build_signature(this->key, "EMSA1(SHA-1)",
								   SIG_FORMAT_DER_SEQUENCE, data, signature);
		case SIGN_ECDSA_WITH_SHA256_DER:
			return build_signature(this->key, "EMSA1(SHA-256)",
								   SIG_FORMAT_DER_SEQUENCE, data, signature);
		case SIGN_ECDSA_WITH_SHA384_DER:
			return build_signature(this->key, "EMSA1(SHA-384)",
								   SIG_FORMAT_DER_SEQUENCE, data, signature);
		case SIGN_ECDSA_WITH_SHA512_DER:
			return build_signature(this->key, "EMSA1(SHA-512)",
								   SIG_FORMAT_DER_SEQUENCE, data, signature);
		/* r||s -> Botan::IEEE_1363 */
		case SIGN_ECDSA_256:
			return build_signature(this->key, "EMSA1(SHA-256)",
								   SIG_FORMAT_IEEE_1363, data, signature);
		case SIGN_ECDSA_384:
			return build_signature(this->key, "EMSA1(SHA-384)",
								   SIG_FORMAT_IEEE_1363, data, signature);
		case SIGN_ECDSA_521:
			return build_signature(this->key, "EMSA1(SHA-512)",
								   SIG_FORMAT_IEEE_1363, data, signature);
		default:
			DBG1(DBG_LIB, "signature scheme %N not supported via botan",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(private_key_t, decrypt, bool,
	private_botan_ec_private_key_t *this, encryption_scheme_t scheme,
	chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "EC private key decryption not implemented");
	return FALSE;
}

METHOD(private_key_t, get_keysize, int,
	private_botan_ec_private_key_t *this)
{
	botan_mp_t p;
	size_t bits = 0;

	if (botan_mp_init(&p))
	{
		return 0;
	}

	if (botan_privkey_get_field(p, this->key, "p") ||
		botan_mp_num_bits(p, &bits))
	{
		botan_mp_destroy(p);
		return 0;
	}

	botan_mp_destroy(p);
	return bits;
}

METHOD(private_key_t, get_type, key_type_t,
	private_botan_ec_private_key_t *this)
{
	return KEY_ECDSA;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_botan_ec_private_key_t *this)
{
	public_key_t *public;
	botan_pubkey_t pubkey;
	chunk_t key = chunk_empty;

	if (botan_privkey_export_pubkey(&pubkey, this->key))
	{
		return FALSE;
	}

	if (botan_pubkey_export(pubkey, NULL, &key.len,
							BOTAN_PRIVKEY_EXPORT_FLAG_DER)
		!= BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE)
	{
		botan_pubkey_destroy(pubkey);
		return FALSE;
	}

	key = chunk_alloc(key.len);

	if (botan_pubkey_export(pubkey, key.ptr, &key.len,
							BOTAN_PRIVKEY_EXPORT_FLAG_DER))
	{
		chunk_free(&key);
		botan_pubkey_destroy(pubkey);
		return FALSE;
	}

	public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ECDSA,
								BUILD_BLOB_ASN1_DER, key, BUILD_END);

	chunk_free(&key);
	botan_pubkey_destroy(pubkey);
	return public;
}

METHOD(private_key_t, get_fingerprint, bool,
	private_botan_ec_private_key_t *this, cred_encoding_type_t type,
	chunk_t *fingerprint)
{
	botan_pubkey_t pubkey;
	bool success = FALSE;

	/* check the cache before doing the export */
	if (lib->encoding->get_cache(lib->encoding, type, this, fingerprint))
	{
		return TRUE;
	}

	if (botan_privkey_export_pubkey(&pubkey, this->key))
	{
		return FALSE;
	}
	success = botan_get_fingerprint(pubkey, this, type, fingerprint);
	botan_pubkey_destroy(pubkey);
	return success;
}

METHOD(private_key_t, get_encoding, bool,
	private_botan_ec_private_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	switch (type)
	{
		case PRIVKEY_ASN1_DER:
		case PRIVKEY_PEM:
		{
			botan_mp_t x;
			chunk_t pval = chunk_empty;
			bool success = TRUE;

			if (botan_mp_init(&x))
			{
				return FALSE;
			}

			if (botan_privkey_get_field(x, this->key, "x"))
			{
				botan_mp_destroy(x);
				return FALSE;
			}

			if (botan_mp_num_bytes(x, &pval.len))
			{
				botan_mp_destroy(x);
				return FALSE;
			}

			pval = chunk_alloc(pval.len);

			if (botan_mp_to_bin(x, pval.ptr))
			{
				botan_mp_destroy(x);
				return FALSE;
			}

			/* FIXME: this does not include the params, which the parser/loader
			 * below actually requires (and is mandated by RFC 5915). we might
			 * have to store/parse the OID so we can add it here. */
			*encoding = asn1_wrap(ASN1_SEQUENCE, "ms",
								  asn1_integer("c", chunk_from_chars(0x01)),
								  asn1_wrap(ASN1_OCTET_STRING, "s", pval));

			if (type == PRIVKEY_PEM)
			{
				chunk_t asn1_encoding = *encoding;

				success = lib->encoding->encode(lib->encoding, PRIVKEY_PEM,
												NULL, encoding,
												CRED_PART_ECDSA_PRIV_ASN1_DER,
												asn1_encoding, CRED_PART_END);
				chunk_clear(&asn1_encoding);
			}

			botan_mp_destroy(x);
			return success;
		}
		default:
			return FALSE;
	}
}

METHOD(private_key_t, get_ref, private_key_t*,
	private_botan_ec_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(private_key_t, destroy, void,
	private_botan_ec_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, this);
		botan_privkey_destroy(this->key);
		free(this);
	}
}

/**
 * Internal generic constructor
 */
static private_botan_ec_private_key_t *create_empty()
{
	private_botan_ec_private_key_t *this;

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
		.ref = 1,
	);

	return this;
}

/*
 * Described in header
 */
botan_ec_private_key_t *botan_ec_private_key_gen(key_type_t type, va_list args)
{
	private_botan_ec_private_key_t *this;
	botan_rng_t rng;
	u_int key_size = 0;
	const char *curve;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_KEY_SIZE:
				key_size = va_arg(args, u_int);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (!key_size)
	{
		return NULL;
	}

	switch (key_size)
	{
		case 256:
			curve = "secp256r1";
			break;
		case 384:
			curve = "secp384r1";
			break;
		case 521:
			curve = "secp521r1";
			break;
		default:
			DBG1(DBG_LIB, "EC private key size %d not supported via botan",
				 key_size);
			return NULL;
	}

	if (botan_rng_init(&rng, "system"))
	{
		return NULL;
	}

	this = create_empty();

	if (botan_privkey_create_ecdsa(&this->key, rng, curve))
	{
		DBG1(DBG_LIB, "EC private key generation failed");
		botan_rng_destroy(rng);
		free(this);
		return NULL;
	}

	botan_rng_destroy(rng);
	return &this->public;
}

/**
 * ASN.1 definition of a ECPrivateKey structure (RFC 5915)
 */
static const asn1Object_t ecPrivateKeyObjects[] = {
	{ 0, "ECPrivateKey",	ASN1_SEQUENCE,		ASN1_NONE	}, /* 0 */
	{ 1,   "version",		ASN1_INTEGER,		ASN1_BODY	}, /* 1 */
	{ 1,   "privateKey",	ASN1_OCTET_STRING,	ASN1_BODY	}, /* 2 */
	{ 1,   "parameters",	ASN1_EOC,			ASN1_RAW	}, /* 3 */
	{ 1,   "publicKey",		ASN1_BIT_STRING,	ASN1_OPT	}, /* 4 */
	{ 0, "exit",			ASN1_EOC,			ASN1_EXIT	}
};

#define ECPK_PRIVATE_KEY 2
#define ECPK_PRIVATE_KEY_PARAMS 3

/*
 * Described in header
 */
botan_ec_private_key_t *botan_ec_private_key_load(key_type_t type, va_list args)
{
	private_botan_ec_private_key_t *this;
	chunk_t params = chunk_empty, key = chunk_empty;
	chunk_t object, alg_id = chunk_empty, pkcs8 = chunk_empty;
	botan_rng_t rng;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ALGID_PARAMS:
				params = va_arg(args, chunk_t);
				continue;
			case BUILD_BLOB_ASN1_DER:
				key = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	/*
	 * botan expects a PKCS#8 private key, so we build one
	 * RFC 5282 mandates ECParameters as part of the algorithmIdentifier
	 */
	if (params.len != 0)
	{
		/* if ECDomainParameters is passed, just append it */
		alg_id = asn1_algorithmIdentifier_params(OID_EC_PUBLICKEY,
												 chunk_clone(params));
	}
	else
	{
		/*
		 * no explicit ECParameters passed, so we extract them from the
		 * ECPrivateKey structure and append it to the algorithmIdentifier
		 */
		asn1_parser_t *parser;
		int objectID;

		parser = asn1_parser_create(ecPrivateKeyObjects, key);
		parser->set_flags(parser, FALSE, TRUE);

		while (parser->iterate(parser, &objectID, &object))
		{
			if (objectID == ECPK_PRIVATE_KEY_PARAMS)
			{
				if (!asn1_parse_simple_object(&object, ASN1_CONTEXT_C_0, 0,
											  "parameters"))
				{
					parser->destroy(parser);
					return NULL;
				}

				if (asn1_unwrap(&object, &params) != ASN1_OID)
				{
					parser->destroy(parser);
					return NULL;
				}
				break;
			}
		}

		parser->destroy(parser);
		alg_id = asn1_algorithmIdentifier_params(OID_EC_PUBLICKEY,
										asn1_simple_object(ASN1_OID, params));
	}

	pkcs8 = asn1_wrap(ASN1_SEQUENCE, "mms",
					  asn1_integer("c", chunk_from_chars(0x00)),
					  alg_id,
					  asn1_wrap(ASN1_OCTET_STRING, "c", key));

	this = create_empty();

	if (botan_rng_init(&rng, "user"))
	{
		chunk_clear(&pkcs8);
		free(this);
		return NULL;
	}

	if (botan_privkey_load(&this->key, rng, pkcs8.ptr, pkcs8.len, NULL))
	{
		chunk_clear(&pkcs8);
		botan_rng_destroy(rng);
		free(this);
		return NULL;
	}

	chunk_clear(&pkcs8);
	botan_rng_destroy(rng);
	return &this->public;
}

#endif
