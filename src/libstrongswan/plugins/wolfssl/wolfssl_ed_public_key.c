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

#ifdef HAVE_ED25519

#include "wolfssl_ed_public_key.h"

#include <utils/debug.h>

#include <wolfssl/wolfcrypt/ed25519.h>

typedef struct private_public_key_t private_public_key_t;

/**
 * Private data
 */
struct private_public_key_t {

	/**
	 * Public interface
	 */
	public_key_t public;

	/**
	 * Key object
	 */
	ed25519_key key;

	/**
	 * Key type
	 */
	key_type_t type;

	/**
	 * Reference counter
	 */
	refcount_t ref;
};


METHOD(public_key_t, get_type, key_type_t,
	private_public_key_t *this)
{
	return this->type;
}

METHOD(public_key_t, verify, bool,
	private_public_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t signature)
{
	int ret;
	int res;
	byte dummy[1];

	if (this->type == KEY_ED25519 && scheme != SIGN_ED25519)
	{
		DBG1(DBG_LIB, "signature scheme %N not supported by %N key",
			 signature_scheme_names, scheme, key_type_names, this->type);
		return FALSE;
	}

	if (data.ptr == NULL && data.len == 0)
	{
		data.ptr = dummy;
	}

	ret = wc_ed25519_verify_msg(signature.ptr, signature.len, data.ptr,
								data.len, &res, &this->key);
	return ret == 0 && res == 1;
}

METHOD(public_key_t, encrypt, bool,
	private_public_key_t *this, encryption_scheme_t scheme,
	chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "encryption scheme %N not supported", encryption_scheme_names,
		 scheme);
	return FALSE;
}

METHOD(public_key_t, get_keysize, int,
	private_public_key_t *this)
{
	return ED25519_KEY_SIZE * 8;
}

/**
 * Calculate fingerprint from an EdDSA key, also used in ed private key.
 */
bool wolfssl_ed_fingerprint(ed25519_key *key, cred_encoding_type_t type,
							chunk_t *fp)
{
	hasher_t *hasher;
	chunk_t blob;
	word32 len;
	int ret;

	if (lib->encoding->get_cache(lib->encoding, type, key, fp))
	{
		return TRUE;
	}
	switch (type)
	{
		case KEYID_PUBKEY_SHA1:
			len = ED25519_PUB_KEY_SIZE;
			blob = chunk_alloca(len);
			if (wc_ed25519_export_public(key, blob.ptr, &len) != 0)
			{
				return FALSE;
			}
			break;
		case KEYID_PUBKEY_INFO_SHA1:
			len = ED25519_PUB_KEY_SIZE + 40;
			blob = chunk_alloca(len);
			ret = wc_Ed25519PublicKeyToDer(key, blob.ptr, blob.len, 1);
			if (ret < 0)
			{
				return FALSE;
			}
			blob.len = ret;
			break;
		default:
			return FALSE;
	}
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher || !hasher->allocate_hash(hasher, blob, fp))
	{
		DBG1(DBG_LIB, "SHA1 not supported, fingerprinting failed");
		DESTROY_IF(hasher);
		return FALSE;
	}
	hasher->destroy(hasher);
	lib->encoding->cache(lib->encoding, type, key, *fp);
	return TRUE;
}

METHOD(public_key_t, get_fingerprint, bool,
	private_public_key_t *this, cred_encoding_type_t type, chunk_t *fingerprint)
{
	return wolfssl_ed_fingerprint(&this->key, type, fingerprint);
}

METHOD(public_key_t, get_encoding, bool,
	private_public_key_t *this, cred_encoding_type_t type, chunk_t *encoding)
{
	bool success = TRUE;
	int ret;

	*encoding = chunk_alloc(ED25519_PUB_KEY_SIZE + 32);
	ret = wc_Ed25519PublicKeyToDer(&this->key, encoding->ptr, encoding->len, 1);
	if (ret < 0)
	{
		return FALSE;
	}
	encoding->len = ret;

	if (type != PUBKEY_SPKI_ASN1_DER)
	{
		chunk_t asn1_encoding = *encoding;

		success = lib->encoding->encode(lib->encoding, type,
								NULL, encoding, CRED_PART_EDDSA_PUB_ASN1_DER,
								asn1_encoding, CRED_PART_END);
		chunk_clear(&asn1_encoding);
	}
	return success;
}

METHOD(public_key_t, get_ref, public_key_t*,
	private_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public;
}

METHOD(public_key_t, destroy, void,
	private_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, &this->key);
		wc_ed25519_free(&this->key);
		free(this);
	}
}

/**
 * Generic private constructor
 */
static private_public_key_t *create_empty(key_type_t type)
{
	private_public_key_t *this;

	INIT(this,
		.public = {
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
		.type = type,
		.ref = 1,
	);
	if (wc_ed25519_init(&this->key) != 0)
	{
		free(this);
		return NULL;
	}

	return this;
}

/*
 * Described in header
 */
public_key_t *wolfssl_ed_public_key_load(key_type_t type, va_list args)
{
	private_public_key_t *this;
	chunk_t blob = chunk_empty, pub = chunk_empty;
	int idx;
	int ret = -1;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_EDDSA_PUB:
				pub = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	this = create_empty(type);
	if (this == NULL)
	{
		return NULL;
	}

	if (pub.len)
	{
		ret = wc_ed25519_import_public(pub.ptr, pub.len, &this->key);
	}
	else if (blob.len)
	{
		idx = 0;
		ret = wc_Ed25519PublicKeyDecode(blob.ptr, &idx, &this->key, blob.len);
	}
	if (ret != 0)
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

#endif /* HAVE_ED25519 */
