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

#ifndef NO_RSA

#include "wolfssl_rsa_public_key.h"
#include "wolfssl_util.h"

#include <crypto/hashers/hasher.h>
#include <utils/debug.h>
#include <credentials/keys/signature_params.h>

#include <wolfssl/wolfcrypt/rsa.h>


typedef struct private_wolfssl_rsa_public_key_t private_wolfssl_rsa_public_key_t;

/**
 * Private data structure with signing context.
 */
struct private_wolfssl_rsa_public_key_t {
	/**
	 * Public interface for this signer.
	 */
	wolfssl_rsa_public_key_t public;

	/**
	 * RSA key object from wolfSSL.
	 */
	RsaKey rsa;

	/**
	 * Random number generator to use with RSA operations.
	 */
	WC_RNG rng;

	/**
	 * reference counter
	 */
	refcount_t ref;
};


/**
 * Verify RSA signature
 */
static bool verify_signature(private_wolfssl_rsa_public_key_t *this,
							 chunk_t data, chunk_t signature)
{
	bool success = FALSE;
	int len = wc_RsaEncryptSize(&this->rsa);
	u_char *buf;
	u_char *p;

	if (signature.len > len)
	{
		signature = chunk_skip(signature, signature.len - len);
	}

	buf = malloc(len);
	memcpy(buf + len - signature.len, signature.ptr, signature.len);
	memset(buf, 0, len - signature.len);

	len = wc_RsaSSL_VerifyInline(buf, len, &p, &this->rsa);
	if (len > 0)
	{
		success = chunk_equals_const(data, chunk_create(p, len));
	}
	free(buf);

	return success;
}

/**
 * Verification of an EMSA PKCS1 signature described in PKCS#1
 */
static bool verify_emsa_pkcs1_signature(private_wolfssl_rsa_public_key_t *this,
										enum wc_HashType hash, chunk_t data,
										chunk_t signature)
{
	bool success = FALSE;
	chunk_t dgst = chunk_empty, encDgst;
	int len;

	encDgst = chunk_alloc(wc_HashGetDigestSize(hash) + 20);
	if (wolfssl_hash_chunk(hash, data, &dgst))
	{
		len = wc_EncodeSignature(encDgst.ptr, dgst.ptr, dgst.len,
								 wc_HashGetOID(hash));
		if (len > 0)
		{
			encDgst.len = len;
			success = verify_signature(this, encDgst, signature);
		}
	}

	chunk_free(&encDgst);
	chunk_free(&dgst);
	return success;
}

#ifdef WC_RSA_PSS
/**
 * Verification of an EMSA PSS signature described in PKCS#1
 */
static bool verify_emsa_pss_signature(private_wolfssl_rsa_public_key_t *this,
									  rsa_pss_params_t *params, chunk_t data,
									  chunk_t signature)
{
	chunk_t dgst = chunk_empty;
	enum wc_HashType hash;
	int mgf;
	bool success = FALSE;
	int len = 0;
	u_char *buf = NULL;
	u_char *p;

	if (!wolfssl_hash2type(params->hash, &hash))
	{
		return FALSE;
	}
	if (!wolfssl_hash2mgf1(params->mgf1_hash, &mgf))
	{
		return FALSE;
	}

	if (wolfssl_hash_chunk(hash, data, &dgst))
	{
		len = wc_RsaEncryptSize(&this->rsa);
		if (signature.len > len)
		{
			signature = chunk_skip(signature, signature.len - len);
		}

		buf = malloc(len);
		memcpy(buf + len - signature.len, signature.ptr, signature.len);
		memset(buf, 0, len - signature.len);

		len = wc_RsaPSS_VerifyInline_ex(buf, len, &p, hash, mgf,
										params->salt_len, &this->rsa);
		if (len > 0)
		{
			success = wc_RsaPSS_CheckPadding_ex(dgst.ptr, dgst.len, p, len,
					hash, params->salt_len, mp_count_bits(&this->rsa.n)) == 0;
		}
	}

	chunk_free(&dgst);
	if (buf != NULL)
	{
		free(buf);
	}

	return success;
}
#endif

METHOD(public_key_t, get_type, key_type_t,
	private_wolfssl_rsa_public_key_t *this)
{
	return KEY_RSA;
}

METHOD(public_key_t, verify, bool,
	private_wolfssl_rsa_public_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t signature)
{
	switch (scheme)
	{
		case SIGN_RSA_EMSA_PKCS1_NULL:
			return verify_signature(this, data, signature);
		case SIGN_RSA_EMSA_PKCS1_SHA2_224:
			return verify_emsa_pkcs1_signature(this, WC_HASH_TYPE_SHA224, data,
											   signature);
		case SIGN_RSA_EMSA_PKCS1_SHA2_256:
			return verify_emsa_pkcs1_signature(this, WC_HASH_TYPE_SHA256, data,
											   signature);
		case SIGN_RSA_EMSA_PKCS1_SHA2_384:
			return verify_emsa_pkcs1_signature(this, WC_HASH_TYPE_SHA384, data,
											   signature);
		case SIGN_RSA_EMSA_PKCS1_SHA2_512:
			return verify_emsa_pkcs1_signature(this, WC_HASH_TYPE_SHA512, data,
											   signature);
		case SIGN_RSA_EMSA_PKCS1_SHA1:
			return verify_emsa_pkcs1_signature(this, WC_HASH_TYPE_SHA, data,
											   signature);
		case SIGN_RSA_EMSA_PKCS1_MD5:
			return verify_emsa_pkcs1_signature(this, WC_HASH_TYPE_MD5, data,
											   signature);
#ifdef WC_RSA_PSS
		case SIGN_RSA_EMSA_PSS:
			return verify_emsa_pss_signature(this, params, data, signature);
#endif
		default:
			DBG1(DBG_LIB, "signature scheme %N not supported in RSA",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(public_key_t, encrypt, bool,
	private_wolfssl_rsa_public_key_t *this, encryption_scheme_t scheme,
	chunk_t plain, chunk_t *crypto)
{
	int padding, mgf, len;
	enum wc_HashType hash;
	char *encrypted;

	switch (scheme)
	{
		case ENCRYPT_RSA_PKCS1:
			padding = WC_RSA_PKCSV15_PAD;
			hash = WC_HASH_TYPE_NONE;
			mgf = WC_MGF1NONE;
			break;
#ifndef WC_NO_RSA_OAEP
	#ifndef NO_SHA
		case ENCRYPT_RSA_OAEP_SHA1:
			padding = WC_RSA_OAEP_PAD;
			hash = WC_HASH_TYPE_SHA;
			mgf = WC_MGF1SHA1;
			break;
	#endif
	#ifdef WOLFSSL_SHA224
		case ENCRYPT_RSA_OAEP_SHA224:
			padding = WC_RSA_OAEP_PAD;
			hash = WC_HASH_TYPE_SHA224;
			mgf = WC_MGF1SHA224;
			break;
	#endif
	#ifndef NO_SHA256
		case ENCRYPT_RSA_OAEP_SHA256:
			padding = WC_RSA_OAEP_PAD;
			hash = WC_HASH_TYPE_SHA256;
			mgf = WC_MGF1SHA256;
			break;
	#endif
	#ifdef WOLFSSL_SHA384
		case ENCRYPT_RSA_OAEP_SHA384:
			padding = WC_RSA_OAEP_PAD;
			hash = WC_HASH_TYPE_SHA384;
			mgf = WC_MGF1SHA384;
			break;
	#endif
	#ifdef WOLFSSL_SHA512
		case ENCRYPT_RSA_OAEP_SHA512:
			padding = WC_RSA_OAEP_PAD;
			hash = WC_HASH_TYPE_SHA512;
			mgf = WC_MGF1SHA512;
			break;
	#endif
#endif
		default:
			DBG1(DBG_LIB, "decryption scheme %N not supported via wolfssl",
				 encryption_scheme_names, scheme);
			return FALSE;
	}
	len = wc_RsaEncryptSize(&this->rsa);
	encrypted = malloc(len);
	len = wc_RsaPublicEncrypt_ex(plain.ptr, plain.len, encrypted, len,
								 &this->rsa, &this->rng, padding, hash, mgf,
								 NULL, 0);
	if (len < 0)
	{
		DBG1(DBG_LIB, "RSA encryption failed");
		free(encrypted);
		return FALSE;
	}
	*crypto = chunk_create(encrypted, len);
	return TRUE;
}

METHOD(public_key_t, get_keysize, int,
	private_wolfssl_rsa_public_key_t *this)
{
	return wc_RsaEncryptSize(&this->rsa) * 8;
}

/**
 * Calculate fingerprint from a RSA key, also used in rsa private key.
 */
bool wolfssl_rsa_fingerprint(RsaKey *rsa, cred_encoding_type_t type,
							 chunk_t *fp)
{
	hasher_t *hasher;
	chunk_t key;
	int len;

	if (lib->encoding->get_cache(lib->encoding, type, rsa, fp))
	{
		return TRUE;
	}
	switch (type)
	{
		case KEYID_PUBKEY_SHA1:
			len = wc_RsaEncryptSize(rsa) * 2 + 20;
			key = chunk_alloc(len);
			len = wc_RsaKeyToPublicDer(rsa, key.ptr, len);
			break;
		default:
		{
			chunk_t n = chunk_empty, e = chunk_empty;
			bool success = FALSE;

			if (wolfssl_mp2chunk(&rsa->n, &n) && wolfssl_mp2chunk(&rsa->e, &e))
			{
				success = lib->encoding->encode(lib->encoding, type, rsa, fp,
									CRED_PART_RSA_MODULUS, n,
									CRED_PART_RSA_PUB_EXP, e, CRED_PART_END);
			}
			chunk_free(&n);
			chunk_free(&e);
			return success;
		}
	}
	if (len < 0)
	{
		chunk_free(&key);
		return FALSE;
	}
	key.len = len;

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher || !hasher->allocate_hash(hasher, key, fp))
	{
		DBG1(DBG_LIB, "SHA1 hash algorithm not supported, fingerprinting failed");
		DESTROY_IF(hasher);
		free(key.ptr);
		return FALSE;
	}
	free(key.ptr);
	hasher->destroy(hasher);
	lib->encoding->cache(lib->encoding, type, rsa, *fp);
	return TRUE;
}

METHOD(public_key_t, get_fingerprint, bool,
	private_wolfssl_rsa_public_key_t *this, cred_encoding_type_t type,
	chunk_t *fingerprint)
{
	return wolfssl_rsa_fingerprint(&this->rsa, type, fingerprint);
}

METHOD(public_key_t, get_encoding, bool,
	private_wolfssl_rsa_public_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	bool success = FALSE;
	int len;

	switch (type)
	{
		case PUBKEY_ASN1_DER:
			len = wc_RsaEncryptSize(&this->rsa) * 2 + 20;
			*encoding = chunk_alloc(len);
			len = wc_RsaKeyToPublicDer(&this->rsa, encoding->ptr, len);
			if (len < 0)
			{
				DBG1(DBG_LIB, "Public Der failed, get encoding failed");
				chunk_free(encoding);
				return FALSE;
			}
			encoding->len = len;
			return TRUE;
		default:
		{
			chunk_t n = chunk_empty, e = chunk_empty;

			if (wolfssl_mp2chunk(&this->rsa.n, &n) &&
				wolfssl_mp2chunk(&this->rsa.e, &e))
			{
				success = lib->encoding->encode(lib->encoding, type, NULL,
									encoding, CRED_PART_RSA_MODULUS, n,
									CRED_PART_RSA_PUB_EXP, e, CRED_PART_END);
			}
			chunk_free(&n);
			chunk_free(&e);
			return success;
		}
	}
}

METHOD(public_key_t, get_ref, public_key_t*,
	private_wolfssl_rsa_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(public_key_t, destroy, void,
	private_wolfssl_rsa_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, &this->rsa);
		wc_FreeRsaKey(&this->rsa);
		wc_FreeRng(&this->rng);
		free(this);
	}
}

/**
 * Generic private constructor
 */
static private_wolfssl_rsa_public_key_t *create_empty()
{
	private_wolfssl_rsa_public_key_t *this;

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.verify = _verify,
				.encrypt = _encrypt,
				.equals = public_key_equals,
				.get_keysize = _get_keysize,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = public_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.ref = 1,
	);

	if (wc_InitRng(&this->rng) != 0)
	{
		DBG1(DBG_LIB, "Init RNG, rsa public key load failed");
		free(this);
		return NULL;
	}
	if (wc_InitRsaKey(&this->rsa, NULL) != 0)
	{
		DBG1(DBG_LIB, "Init RSA, rsa public key load failed");
		wc_FreeRng(&this->rng);
		free(this);
		return NULL;
	}
	return this;
}

/**
 * See header.
 */
wolfssl_rsa_public_key_t *wolfssl_rsa_public_key_load(key_type_t type,
													  va_list args)
{
	private_wolfssl_rsa_public_key_t *this;
	chunk_t blob, n, e;
	word32 idx;

	n = e = blob = chunk_empty;
	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_RSA_MODULUS:
				n = va_arg(args, chunk_t);
				continue;
			case BUILD_RSA_PUB_EXP:
				e = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	this = create_empty();
	if (this == NULL)
	{
		return NULL;
	}

	if (blob.ptr)
	{
		switch (type)
		{
			case KEY_ANY:
			case KEY_RSA:
				idx = 0;
				if (wc_RsaPublicKeyDecode(blob.ptr, &idx, &this->rsa,
										  blob.len) != 0)
				{
					DBG1(DBG_LIB, "Public , rsa public key load failed");
					destroy(this);
					return NULL;
				}
				break;
			default:
				destroy(this);
				return NULL;
		}
		return &this->public;
	}
	else if (n.ptr && e.ptr && type == KEY_RSA)
	{
		if (wc_RsaPublicKeyDecodeRaw(n.ptr, n.len, e.ptr, e.len,
									 &this->rsa) != 0)
		{
			destroy(this);
			return NULL;
		}
		return &this->public;
	}
	destroy(this);
	return NULL;
}

#endif /* NO_RSA */
