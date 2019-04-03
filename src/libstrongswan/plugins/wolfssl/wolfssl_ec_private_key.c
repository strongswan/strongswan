/*
 * Copyright (C) 2019 Sean Parkinson, wolfSSL Inc.
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

#include "wolfssl_common.h"

#ifdef HAVE_ECC_SIGN

#include "wolfssl_ec_private_key.h"
#include "wolfssl_ec_public_key.h"
#include "wolfssl_util.h"

#include <asn1/asn1.h>
#include <asn1/oid.h>

#include <utils/debug.h>

#include <wolfssl/wolfcrypt/ecc.h>


typedef struct private_wolfssl_ec_private_key_t private_wolfssl_ec_private_key_t;

/**
 * Private data of a wolfssl_ec_private_key_t object.
 */
struct private_wolfssl_ec_private_key_t {
	/**
	 * Public interface for this signer.
	 */
	wolfssl_ec_private_key_t public;

	/**
	 * Key size
	 */
	int keysize;

	/**
	 * EC key object
	 */
	ecc_key ec;

	/**
	 * Random number generator
	 */
	WC_RNG rng;

	/**
	 * reference count
	 */
	refcount_t ref;
};

/* from ec public key */
bool wolfssl_ec_fingerprint(ecc_key *ec, cred_encoding_type_t type, chunk_t *fp);

/**
 * Build a signature as in RFC 4754
 */
static bool build_signature(private_wolfssl_ec_private_key_t *this,
							chunk_t hash, chunk_t *signature)
{
	bool success = FALSE;
	mp_int r, s;

	if (mp_init(&r) != 0)
	{
		return FALSE;
	}
	if (mp_init(&s) != 0)
	{
		mp_free(&r);
		return FALSE;
	}
	if (wc_ecc_sign_hash_ex(hash.ptr, hash.len, &this->rng, &this->ec, &r,
							&s) == 0)
	{
		success = wolfssl_mp_cat(this->ec.dp->size * 2, &r, &s, signature);
	}

	mp_free(&s);
	mp_free(&r);
	
	return success;
}

/**
 * Build a RFC 4754 signature for a specified curve and hash algorithm
 */
static bool build_curve_signature(private_wolfssl_ec_private_key_t *this,
		signature_scheme_t scheme, enum wc_HashType hash, ecc_curve_id curve_id,
		chunk_t data, chunk_t *signature)
{
	bool success = FALSE;
	chunk_t dgst = chunk_empty;

	if (curve_id != this->ec.dp->id)
	{
		DBG1(DBG_LIB, "signature scheme %N not supported by private key",
			signature_scheme_names, scheme);
		return FALSE;
	}
	if (wolfssl_hash_chunk(hash, data, &dgst))
	{
		success = build_signature(this, dgst, signature);
	}
	chunk_free(&dgst);
	return success;
}

/**
 * Build a DER encoded signature as in RFC 3279
 */
static bool build_der_signature(private_wolfssl_ec_private_key_t *this,
		enum wc_HashType hash, chunk_t data, chunk_t *signature)
{
	bool success = FALSE;
	chunk_t dgst = chunk_empty;
	int ret;
	word32 len;

	if (wolfssl_hash_chunk(hash, data, &dgst))
	{
		*signature = chunk_alloc(this->ec.dp->size * 2 + 10);
		len = signature->len;
		ret = wc_ecc_sign_hash(dgst.ptr, dgst.len, signature->ptr, &len,
							   &this->rng, &this->ec);
		if (ret == 0)
		{
			signature->len = len;
			success = TRUE;
		}
		else
		{
			chunk_free(signature);
		}
	}

	chunk_free(&dgst);
	return success;
}

METHOD(private_key_t, sign, bool,
	private_wolfssl_ec_private_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t *signature)
{
	switch (scheme)
	{
		case SIGN_ECDSA_WITH_NULL:
			return build_signature(this, data, signature);
	#ifndef NO_SHA
		case SIGN_ECDSA_WITH_SHA1_DER:
			return build_der_signature(this, WC_HASH_TYPE_SHA, data, signature);
	#endif
	#ifndef NO_SHA256
		case SIGN_ECDSA_WITH_SHA256_DER:
			return build_der_signature(this, WC_HASH_TYPE_SHA256, data,
									   signature);
	#endif
	#ifdef WOLFSSL_SHA384
		case SIGN_ECDSA_WITH_SHA384_DER:
			return build_der_signature(this, WC_HASH_TYPE_SHA384, data,
									   signature);
	#endif
	#ifdef WOLFSSL_SHA512
		case SIGN_ECDSA_WITH_SHA512_DER:
			return build_der_signature(this, WC_HASH_TYPE_SHA512, data,
									   signature);
	#endif
	#ifndef NO_SHA256
		case SIGN_ECDSA_256:
			return build_curve_signature(this, scheme, WC_HASH_TYPE_SHA256,
										 ECC_SECP256R1, data, signature);
	#endif
	#ifdef WOLFSSL_SHA384
		case SIGN_ECDSA_384:
			return build_curve_signature(this, scheme, WC_HASH_TYPE_SHA384,
										 ECC_SECP384R1, data, signature);
	#endif
	#ifdef WOLFSSL_SHA512
		case SIGN_ECDSA_521:
			return build_curve_signature(this, scheme, WC_HASH_TYPE_SHA512,
										 ECC_SECP521R1, data, signature);
	#endif
		default:
			DBG1(DBG_LIB, "signature scheme %N not supported",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(private_key_t, decrypt, bool,
	private_wolfssl_ec_private_key_t *this, encryption_scheme_t scheme,
	chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "EC private key decryption not implemented");
	return FALSE;
}

METHOD(private_key_t, get_keysize, int,
	private_wolfssl_ec_private_key_t *this)
{
	return this->keysize;
}

METHOD(private_key_t, get_type, key_type_t,
	private_wolfssl_ec_private_key_t *this)
{
	return KEY_ECDSA;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_wolfssl_ec_private_key_t *this)
{
	public_key_t *public;
	chunk_t key;
	int ret;

	key = chunk_alloc((this->keysize + 7) / 8 * 5);
	ret = wc_EccPublicKeyToDer(&this->ec, key.ptr, key.len, 1);
	if (ret < 0)
	{
		chunk_free(&key);
		return NULL;
	}
	key.len = ret;

	public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ECDSA,
								BUILD_BLOB_ASN1_DER, key, BUILD_END);
	free(key.ptr);
	return public;
}

METHOD(private_key_t, get_fingerprint, bool,
	private_wolfssl_ec_private_key_t *this, cred_encoding_type_t type,
	chunk_t *fingerprint)
{
	return wolfssl_ec_fingerprint(&this->ec, type, fingerprint);
}

METHOD(private_key_t, get_encoding, bool,
	private_wolfssl_ec_private_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	switch (type)
	{
		case PRIVKEY_ASN1_DER:
		case PRIVKEY_PEM:
		{
			bool success = TRUE;

			*encoding = chunk_alloc(this->keysize * 4 + 30);
			if (wc_EccPrivateKeyToDer(&this->ec, encoding->ptr,
									  encoding->len) < 0)
			{
				chunk_free(encoding);
				return FALSE;
			}

			if (type == PRIVKEY_PEM)
			{
				chunk_t asn1_encoding = *encoding;

				success = lib->encoding->encode(lib->encoding, PRIVKEY_PEM,
								NULL, encoding, CRED_PART_ECDSA_PRIV_ASN1_DER,
								asn1_encoding, CRED_PART_END);
				chunk_clear(&asn1_encoding);
			}
			return success;
		}
		default:
			return FALSE;
	}
}

METHOD(private_key_t, get_ref, private_key_t*,
	private_wolfssl_ec_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(private_key_t, destroy, void,
	private_wolfssl_ec_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, &this->ec);
		wc_FreeRng(&this->rng);
		wc_ecc_free(&this->ec);
		free(this);
	}
}

/**
 * Internal generic constructor
 */
static private_wolfssl_ec_private_key_t *create_empty(void)
{
	private_wolfssl_ec_private_key_t *this;

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

	if (wc_InitRng(&this->rng) < 0)
	{
		DBG1(DBG_LIB, "Random number generation init failed");
		free(this);
		return NULL;
	}

	return this;
}

/*
 * See header.
 */
wolfssl_ec_private_key_t *wolfssl_ec_private_key_gen(key_type_t type,
													 va_list args)
{
	private_wolfssl_ec_private_key_t *this;
	u_int key_size = 0;
	ecc_curve_id curve_id;

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
	this = create_empty();
	this->keysize = key_size;
	switch (key_size)
	{
		case 256:
			curve_id = ECC_SECP256R1;
			break;
		case 384:
			curve_id = ECC_SECP384R1;
			break;
		case 521:
			curve_id = ECC_SECP521R1;
			break;
		default:
			DBG1(DBG_LIB, "EC private key size %d not supported", key_size);
			destroy(this);
			return NULL;
	}

	if (wc_ecc_make_key_ex(&this->rng, (key_size + 7) / 8, &this->ec,
						   curve_id) < 0)
	{
		DBG1(DBG_LIB, "EC private key generation failed", key_size);
		destroy(this);
		return NULL;
	}
	return &this->public;
}

/**
 * See header.
 */
wolfssl_ec_private_key_t *wolfssl_ec_private_key_load(key_type_t type,
													  va_list args)
{
	private_wolfssl_ec_private_key_t *this;
	chunk_t params = chunk_empty;
	chunk_t key = chunk_empty;
	chunk_t alg_id = chunk_empty;
	word32 idx;
	int oid;

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
	if (key.ptr == NULL)
	{
		return NULL;
	}

	this = create_empty();

	idx = 0;
	if (wc_EccPrivateKeyDecode(key.ptr, &idx, &this->ec, key.len) < 0)
	{
		destroy(this);
		return NULL;
	}
	switch (this->ec.dp->id)
	{
		case ECC_SECP256R1:
			this->keysize = 256;
			break;
		case ECC_SECP384R1:
			this->keysize = 384;
			break;
		case ECC_SECP521R1:
			this->keysize = 521;
			break;
		default:
			break;
	}

	if (params.ptr)
	{
		/* if ECParameters is passed, check we guessed correct */
		alg_id = asn1_algorithmIdentifier_params(OID_EC_PUBLICKEY,
												 chunk_clone(params));
		if (asn1_unwrap(&params, &params) == ASN1_OID)
		{
			oid = asn1_known_oid(params);
			switch (oid)
			{
				case OID_PRIME256V1:
					if (this->ec.dp->id != ECC_SECP256R1)
					{
						oid = OID_UNKNOWN;
					}
					break;
				case OID_SECT384R1:
					if (this->ec.dp->id != ECC_SECP384R1)
					{
						oid = OID_UNKNOWN;
					}
					break;
				case OID_SECT521R1:
					if (this->ec.dp->id != ECC_SECP521R1)
					{
						oid = OID_UNKNOWN;
					}
					break;
				default:
					oid = OID_UNKNOWN;
					break;
			}
		}
		chunk_free(&alg_id);
		if (oid == OID_UNKNOWN)
		{
			DBG1(DBG_LIB, "parameters do not match private key data");
			destroy(this);
			return NULL;
		}
	}

	return &this->public;
}
#endif /* HAVE_ECC_SIGN */
