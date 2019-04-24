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

#include "wolfssl_ed_private_key.h"

#include <utils/debug.h>

#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/asn.h>

typedef struct private_private_key_t private_private_key_t;

/**
 * Private data
 */
struct private_private_key_t {

	/**
	 * Public interface
	 */
	private_key_t public;

	/**
	 * Key object
	 */
	ed25519_key key;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

/* from ed public key */
bool wolfssl_ed_fingerprint(ed25519_key *key, cred_encoding_type_t type,
							chunk_t *fp);

METHOD(private_key_t, sign, bool,
	private_private_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t *signature)
{
	word32 len;
	byte dummy[1];
	int ret;

	if (scheme != SIGN_ED25519)
	{
		DBG1(DBG_LIB, "signature scheme %N not supported by %N key",
			 signature_scheme_names, scheme, key_type_names, KEY_ED25519);
		return FALSE;
	}

	if (!data.ptr && !data.len)
	{
		data.ptr = dummy;
	}

	len = ED25519_SIG_SIZE;
	*signature = chunk_alloc(len);
	ret = wc_ed25519_sign_msg(data.ptr, data.len, signature->ptr, &len,
							  &this->key);
	return ret == 0;
}

METHOD(private_key_t, decrypt, bool,
	private_private_key_t *this, encryption_scheme_t scheme,
	chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "EdDSA private key decryption not implemented");
	return FALSE;
}

METHOD(private_key_t, get_keysize, int,
	private_private_key_t *this)
{
	return ED25519_KEY_SIZE * 8;
}

METHOD(private_key_t, get_type, key_type_t,
	private_private_key_t *this)
{
	return KEY_ED25519;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_private_key_t *this)
{
	public_key_t *public;
	chunk_t key;
	word32 len = ED25519_PUB_KEY_SIZE;

	key = chunk_alloca(len);
	if (wc_ed25519_export_public(&this->key, key.ptr, &len) != 0)
	{
		return NULL;
	}
	public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ED25519,
								BUILD_EDDSA_PUB, key, BUILD_END);
	return public;
}

METHOD(private_key_t, get_fingerprint, bool,
	private_private_key_t *this, cred_encoding_type_t type,
	chunk_t *fingerprint)
{
	return wolfssl_ed_fingerprint(&this->key, type, fingerprint);
}

METHOD(private_key_t, get_encoding, bool,
	private_private_key_t *this, cred_encoding_type_t type, chunk_t *encoding)
{
	int ret;

	switch (type)
	{
		case PRIVKEY_ASN1_DER:
		case PRIVKEY_PEM:
		{
			bool success = TRUE;

			/* +4 is for the two octet strings */
			*encoding = chunk_alloc(ED25519_PRV_KEY_SIZE + 2 * MAX_SEQ_SZ +
									MAX_VERSION_SZ + MAX_ALGO_SZ + 4);
			ret = wc_Ed25519PrivateKeyToDer(&this->key, encoding->ptr,
											encoding->len);
			if (ret < 0)
			{
				chunk_free(encoding);
				return FALSE;
			}
			encoding->len = ret;

			if (type == PRIVKEY_PEM)
			{
				chunk_t asn1_encoding = *encoding;

				success = lib->encoding->encode(lib->encoding, PRIVKEY_PEM,
								NULL, encoding, CRED_PART_EDDSA_PRIV_ASN1_DER,
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
	private_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public;
}

METHOD(private_key_t, destroy, void,
	private_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		lib->encoding->clear_cache(lib->encoding, &this->key);
		wc_ed25519_free(&this->key);
		free(this);
	}
}

/**
 * Internal generic constructor
 */
static private_private_key_t *create_internal()
{
	private_private_key_t *this;

	INIT(this,
		.public = {
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
		.ref = 1,
	);

	if (wc_ed25519_init(&this->key) != 0)
	{
		free(this);
		this = NULL;
	}
	return this;
}

/*
 * Described in header
 */
private_key_t *wolfssl_ed_private_key_gen(key_type_t type, va_list args)
{
	private_private_key_t *this;
	WC_RNG rng;
	int ret;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_KEY_SIZE:
				/* just ignore the key size */
				va_arg(args, u_int);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	this = create_internal();
	if (!this)
	{
		return NULL;
	}

	if (wc_InitRng(&rng) != 0)
	{
		DBG1(DBG_LIB, "initializing random failed");
		destroy(this);
		return NULL;
	}
	ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &this->key);
	wc_FreeRng(&rng);

	if (ret < 0)
	{
		DBG1(DBG_LIB, "generating %N key failed", key_type_names, type);
		destroy(this);
		return NULL;
	}
	return &this->public;
}

/**
 * Fix the internal state if only the private key is set
 */
static int set_public_key(private_private_key_t *this)
{
	int ret = 0;

	if (!this->key.pubKeySet)
	{
		ret = wc_ed25519_make_public(&this->key, this->key.p,
									 ED25519_PUB_KEY_SIZE);
		if (ret == 0)
		{
			/* put public key after private key in the same buffer */
			memmove(this->key.k + ED25519_KEY_SIZE, this->key.p,
					ED25519_PUB_KEY_SIZE);
			this->key.pubKeySet = 1;
		}
	}
	return ret;
}

/*
 * Described in header
 */
private_key_t *wolfssl_ed_private_key_load(key_type_t type, va_list args)
{
	private_private_key_t *this;
	chunk_t blob = chunk_empty, priv = chunk_empty;
	int idx;
	int ret = -1;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_EDDSA_PRIV_ASN1_DER:
				priv = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	this = create_internal();
	if (!this)
	{
		return NULL;
	}

	if (priv.len)
	{
		/* check for ASN.1 wrapped key (Octet String == 0x04) */
		if (priv.len == ED25519_KEY_SIZE + 2 && priv.ptr[0] == 0x04 &&
												priv.ptr[1] == ED25519_KEY_SIZE)
		{
			priv = chunk_skip(priv, 2);
		}
		ret = wc_ed25519_import_private_only(priv.ptr, priv.len, &this->key);
	}
	else if (blob.len)
	{
		idx = 0;
		ret = wc_Ed25519PrivateKeyDecode(blob.ptr, &idx, &this->key, blob.len);
	}
	if (ret == 0)
	{
		ret = set_public_key(this);
	}
	if (ret != 0)
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

#endif /* HAVE_ED25519 */
