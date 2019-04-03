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

#ifdef HAVE_ECC_VERIFY

#include "wolfssl_ec_public_key.h"
#include "wolfssl_util.h"

#include <utils/debug.h>

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>


typedef struct private_wolfssl_ec_public_key_t private_wolfssl_ec_public_key_t;

/**
 * Private data structure with signing context.
 */
struct private_wolfssl_ec_public_key_t {
	/**
	 * Public interface for this signer.
	 */
	wolfssl_ec_public_key_t public;

	/**
	 * Key size
	 */
	int keysize;

	/**
	 * EC key object
	 */
	ecc_key ec;

	/**
	 * reference counter
	 */
	refcount_t ref;
};

/**
 * Verification of a signature as in RFC 4754
 */
static bool verify_signature(private_wolfssl_ec_public_key_t *this,
							 chunk_t hash, chunk_t signature)
{
	int stat = 1;
	int ret = -1;
	mp_int r, s;

	if (mp_init(&r) < 0)
	{
		return FALSE;
	}
	if (mp_init(&s) < 0)
	{
		mp_free(&r);
		return FALSE;
	}

	if (wolfssl_mp_split(signature, &r, &s))
	{
		ret = wc_ecc_verify_hash_ex(&r, &s, hash.ptr, hash.len, &stat,
									&this->ec);
	}

	mp_free(&s);
	mp_free(&r);

	return ret == 0 && stat == 1;
}

/**
 * Verify a RFC 4754 signature for a specified curve and hash algorithm
 */
static bool verify_curve_signature(private_wolfssl_ec_public_key_t *this,
		signature_scheme_t scheme, enum wc_HashType hash, ecc_curve_id curve_id,
		chunk_t data, chunk_t signature)
{
	bool success = FALSE;
	chunk_t dgst;

	if (curve_id != this->ec.dp->id)
	{
		DBG1(DBG_LIB, "signature scheme %N not supported by private key",
			 signature_scheme_names, scheme);
		return FALSE;
	}

	if (wolfssl_hash_chunk(hash, data, &dgst))
	{
		success = verify_signature(this, dgst, signature);
	}

	chunk_free(&dgst);
	return success;
}

/**
 * Verification of a DER encoded signature as in RFC 3279
 */
static bool verify_der_signature(private_wolfssl_ec_public_key_t *this,
		enum wc_HashType hash, chunk_t data, chunk_t signature)
{
	bool success = FALSE;
	chunk_t dgst;
	int stat = 1;
	int ret;

	/* remove any preceding 0-bytes from signature */
	while (signature.len && signature.ptr[0] == 0x00)
	{
		signature = chunk_skip(signature, 1);
	}
	if (wolfssl_hash_chunk(hash, data, &dgst))
	{
		ret = wc_ecc_verify_hash(signature.ptr, signature.len, dgst.ptr,
								 dgst.len, &stat, &this->ec);
		if (ret == 0 && stat == 1)
		{
			success = TRUE;
		}
	}

	chunk_free(&dgst);
	return success;
}

METHOD(public_key_t, get_type, key_type_t,
	private_wolfssl_ec_public_key_t *this)
{
	return KEY_ECDSA;
}

METHOD(public_key_t, verify, bool,
	private_wolfssl_ec_public_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t signature)
{
	switch (scheme)
	{
	#ifndef NO_SHA
		case SIGN_ECDSA_WITH_SHA1_DER:
			return verify_der_signature(this, WC_HASH_TYPE_SHA, data,
										signature);
	#endif
	#ifndef NO_SHA256
		case SIGN_ECDSA_WITH_SHA256_DER:
			return verify_der_signature(this, WC_HASH_TYPE_SHA256, data,
										signature);
	#endif
	#ifdef WOLFSSL_SHA384
		case SIGN_ECDSA_WITH_SHA384_DER:
			return verify_der_signature(this, WC_HASH_TYPE_SHA384, data,
										signature);
	#endif
	#ifdef WOLFSSL_SHA512
		case SIGN_ECDSA_WITH_SHA512_DER:
			return verify_der_signature(this, WC_HASH_TYPE_SHA512, data,
										signature);
	#endif
		case SIGN_ECDSA_WITH_NULL:
			return verify_signature(this, data, signature);
	#ifndef NO_SHA256
		case SIGN_ECDSA_256:
			return verify_curve_signature(this, scheme, WC_HASH_TYPE_SHA256,
										  ECC_SECP256R1, data, signature);
	#endif
	#ifdef WOLFSSL_SHA384
		case SIGN_ECDSA_384:
			return verify_curve_signature(this, scheme, WC_HASH_TYPE_SHA384,
										  ECC_SECP384R1, data, signature);
	#endif
	#ifdef WOLFSSL_SHA512
		case SIGN_ECDSA_521:
			return verify_curve_signature(this, scheme, WC_HASH_TYPE_SHA512,
										  ECC_SECP521R1, data, signature);
	#endif
		default:
			DBG1(DBG_LIB, "signature scheme %N not supported in EC",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(public_key_t, encrypt, bool,
	private_wolfssl_ec_public_key_t *this, encryption_scheme_t scheme,
	chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "EC public key encryption not implemented");
	return FALSE;
}

METHOD(public_key_t, get_keysize, int,
	private_wolfssl_ec_public_key_t *this)
{
	return this->keysize;
}

/**
 * Calculate fingerprint from a EC_KEY, also used in ec private key.
 */
bool wolfssl_ec_fingerprint(ecc_key *ec, cred_encoding_type_t type, chunk_t *fp)
{
	hasher_t *hasher;
	chunk_t key;
	int ret;
	bool success;

	if (lib->encoding->get_cache(lib->encoding, type, ec, fp))
	{
		return TRUE;
	}

	key = chunk_alloc(ec->dp->size * 4 + 30);
	ret = wc_EccPublicKeyToDer(ec, key.ptr, key.len, 1);
	if (ret < 0)
	{
		free(key.ptr);
		return FALSE;
	}
	key.len = ret;

	switch (type)
	{
		case KEYID_PUBKEY_SHA1:
			break;
		default:
			success = lib->encoding->encode(lib->encoding, type, ec, fp,
											CRED_PART_ECDSA_PUB_ASN1_DER, key,
											CRED_PART_END);
			chunk_free(&key);
			return success;
	}

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher || !hasher->allocate_hash(hasher, key, fp))
	{
		DBG1(DBG_LIB, "SHA1 hash algorithm not supported, fingerprinting failed");
		DESTROY_IF(hasher);
		free(key.ptr);
		return FALSE;
	}
	hasher->destroy(hasher);
	free(key.ptr);
	lib->encoding->cache(lib->encoding, type, ec, *fp);
	return TRUE;
}

METHOD(public_key_t, get_fingerprint, bool,
	private_wolfssl_ec_public_key_t *this, cred_encoding_type_t type,
	chunk_t *fingerprint)
{
	return wolfssl_ec_fingerprint(&this->ec, type, fingerprint);
}

METHOD(public_key_t, get_encoding, bool,
	private_wolfssl_ec_public_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	bool success = TRUE;
	int ret;

	*encoding = chunk_alloc(this->ec.dp->size * 2 + 30);
	ret = wc_EccPublicKeyToDer(&this->ec, encoding->ptr, encoding->len, 1);
	if (ret < 0)
	{
		chunk_free(encoding);
		return FALSE;
	}
	encoding->len = ret;

	if (type != PUBKEY_ASN1_DER)
	{
		chunk_t asn1_encoding = *encoding;

		success = lib->encoding->encode(lib->encoding, type,
						NULL, encoding, CRED_PART_ECDSA_PUB_ASN1_DER,
						asn1_encoding, CRED_PART_END);
		chunk_clear(&asn1_encoding);
	}
	return success;
}

METHOD(public_key_t, get_ref, public_key_t*,
	private_wolfssl_ec_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(public_key_t, destroy, void,
	private_wolfssl_ec_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, &this->ec);
		wc_ecc_free(&this->ec);
		free(this);
	}
}

/**
 * Generic private constructor
 */
static private_wolfssl_ec_public_key_t *create_empty()
{
	private_wolfssl_ec_public_key_t *this;

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.verify = _verify,
				.encrypt = _encrypt,
				.get_keysize = _get_keysize,
				.equals = public_key_equals,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = public_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.ref = 1,
	);

	if (wc_ecc_init(&this->ec) < 0)
	{
		free(this);
		return NULL;
	}

	return this;
}

/**
 * See header.
 */
wolfssl_ec_public_key_t *wolfssl_ec_public_key_load(key_type_t type,
													va_list args)
{
	private_wolfssl_ec_public_key_t *this;
	chunk_t blob = chunk_empty;
	word32 idx;
	int ret;

	if (type != KEY_ECDSA)
	{
		return NULL;
	}

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	this = create_empty();
	idx = 0;
	ret = wc_EccPublicKeyDecode(blob.ptr, &idx, &this->ec, blob.len);
	if (ret < 0)
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
	return &this->public;
}
#endif /* HAVE_ECC_VERIFY */

