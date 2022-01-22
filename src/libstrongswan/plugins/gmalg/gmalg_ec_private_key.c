/*
 * Copyright (C) 2008-2016 Tobias Brunner
 * Copyright (C) 2009 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
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

#include "gmalg_ec_private_key.h"
#include "gmalg_ec_public_key.h"
#include "gmalg_util.h"
#include "gmalg_hasher.h"

#include <utils/debug.h>

#include <gmalg.h>

typedef struct private_gmalg_ec_private_key_t private_gmalg_ec_private_key_t;

/**
 * Private data of a gmalg_ec_private_key_t object.
 */
struct private_gmalg_ec_private_key_t {
	/**
	 * Public interface for this signer.
	 */
	gmalg_ec_private_key_t public;

	/**
	 * TRUE if the key is from an OpenSSL ENGINE and might not be readable
	 */
	bool engine;

	/**
	 *  key type
	 */
	key_type_t type;

	/**
	 * the cipher device handle
	 */
	void *hDeviceHandle;

	ECCrefPublicKey pubkey[1];
	ECCrefPrivateKey prikey[1];

	/**
	 * reference count
	 */
	refcount_t ref;
};

/* from ec public key */
bool gmalg_ec_fingerprint(ECCrefPublicKey *pubkey, cred_encoding_type_t type, chunk_t *fp);

/**
 * Build a signature as in RFC 4754
 */
static bool build_signature(private_gmalg_ec_private_key_t *this,
							chunk_t hash, chunk_t *signature)
{
	bool built = TRUE;

	*signature  = chunk_alloc(sizeof(ECCSignature));

	GMALG_ExternalSign_ECC(this->hDeviceHandle, this->prikey, hash.ptr, hash.len,
				(ECCSignature *)(signature->ptr));

	return built;
}

/**
 * Build a RFC 4754 signature for a specified curve and hash algorithm
 */
static bool build_curve_signature(private_gmalg_ec_private_key_t *this,
								signature_scheme_t scheme, int nid_hash,
								int nid_curve, chunk_t data, chunk_t *signature)
{
	bool built = FALSE;
	chunk_t hash = chunk_empty;

	if (HASH_SM3 == nid_hash)
	{
		gmalg_hasher_t *h;

		//GMT0009规定SM2-SM3签名需先用ID、公钥计算Z值.后续如果有需要,ID可由params传入
		h = gmalg_hasher_create_ecc(HASH_SM3, &this->pubkey[0], chunk_from_thing(id_default));
		if (h == NULL)
		{
			built = FALSE;
			goto err;
		}

		built = h->hasher.allocate_hash(&h->hasher, data, &hash);
		if (built == FALSE)
			goto err;
	}

	if (hash.ptr)
	{
		built = build_signature(this, hash, signature);
		chunk_free(&hash);
		built = TRUE;
	}
err:
	return built;
}

METHOD(private_key_t, sign, bool,
	private_gmalg_ec_private_key_t *this, signature_scheme_t scheme,
	void *params, chunk_t data, chunk_t *signature)
{
	switch (scheme)
	{
		case SIGN_SM2_WITH_SM3:
			return build_curve_signature(this, scheme, HASH_SM3, KEY_SM2, data, signature);
		default:
			DBG1(DBG_LIB, "signature scheme %N not supported",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(private_key_t, decrypt, bool,
	private_gmalg_ec_private_key_t *this, encryption_scheme_t scheme,
	chunk_t crypto, chunk_t *plain)
{
	DBG1(DBG_LIB, "EC private key decryption, cipher len %d", crypto.len);

	if (crypto.len <= 3 * ECCref_MAX_LEN)
	{
		return FALSE; //C1C3C2,最少需要96字节
	}

	*plain  = chunk_alloc(crypto.len - 3 * ECCref_MAX_LEN);
	memset(plain->ptr, 0, plain->len);

	GMALG_ExternalDecrypt_ECC(this->hDeviceHandle, this->prikey, crypto.ptr, crypto.len, plain->ptr);

	return TRUE;
}

METHOD(private_key_t, get_keysize, int,
	private_gmalg_ec_private_key_t *this)
{
	return sizeof(ECCrefPrivateKey);
}

METHOD(private_key_t, get_type, key_type_t,
	private_gmalg_ec_private_key_t *this)
{
	return this->type;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_gmalg_ec_private_key_t *this)
{
	public_key_t *public;
	chunk_t key;

	gmalg_i2d_ec_pubkey(this->pubkey, &key);

	public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, this->type,
								BUILD_BLOB_ASN1_DER, key, BUILD_END);
	free(key.ptr);
	return public;
}

METHOD(private_key_t, get_fingerprint, bool,
	private_gmalg_ec_private_key_t *this, cred_encoding_type_t type,
	chunk_t *fingerprint)
{
	return gmalg_ec_fingerprint(this->pubkey, type, fingerprint);
}

METHOD(private_key_t, get_encoding, bool,
	private_gmalg_ec_private_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{

	if (this->engine)
	{
		return FALSE;
	}

	switch (type)
	{
		case PRIVKEY_ASN1_DER:
		case PRIVKEY_PEM:
		{
			bool success = TRUE;

			gmalg_i2d_EC_prikey(this->prikey, this->pubkey, encoding);
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
	private_gmalg_ec_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(private_key_t, destroy, void,
	private_gmalg_ec_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		GMALG_CloseDevice(this->hDeviceHandle);
		free(this);
	}
}

/**
 * Internal generic constructor
 */
static private_gmalg_ec_private_key_t *create_empty(void)
{
	private_gmalg_ec_private_key_t *this;

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

	GMALG_OpenDevice(&this->hDeviceHandle);

	return this;
}

/*
 * See header.
 */
gmalg_ec_private_key_t *gmalg_ec_private_key_gen(key_type_t type,
													 va_list args)
{
	private_gmalg_ec_private_key_t *this;
	u_int key_size = 0;

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
	switch (type)
	{
		case KEY_SM2:{
			GMALG_GenerateKeyPair_ECC(this->hDeviceHandle, this->pubkey, this->prikey);
		}break;
		default:{
			DBG1(DBG_LIB, "EC private type %d key size %d not supported", type, key_size);
			destroy(this);
			return NULL;
		}
	}
	this->type = type;
	return &this->public;
}

/**
 * See header.
 */
gmalg_ec_private_key_t *gmalg_ec_private_key_load(key_type_t type,
													  va_list args)
{
	private_gmalg_ec_private_key_t *this;
	chunk_t par = chunk_empty, key = chunk_empty;
	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ALGID_PARAMS:
				par = va_arg(args, chunk_t);
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

	this = create_empty();

	if (par.ptr)
	{
		gmalg_d2i_ec_prikey(this->prikey, this->pubkey, key);
	}
	else if (key.ptr)
	{
		gmalg_d2i_ec_prikey(this->prikey, this->pubkey, key);
	} else
		goto error;

	this->type = type;
	return &this->public;

error:
	destroy(this);
	return NULL;
}
