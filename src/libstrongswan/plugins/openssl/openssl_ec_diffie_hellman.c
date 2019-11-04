/*
 * Copyright (C) 2008-2021 Tobias Brunner
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

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_EC

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
#include <openssl/bn.h>
#endif

#include "openssl_ec_diffie_hellman.h"
#include "openssl_util.h"

#include <utils/debug.h>

typedef struct private_openssl_ec_diffie_hellman_t private_openssl_ec_diffie_hellman_t;

/**
 * Private data of an openssl_ec_diffie_hellman_t object.
 */
struct private_openssl_ec_diffie_hellman_t {
	/**
	 * Public openssl_ec_diffie_hellman_t interface.
	 */
	openssl_ec_diffie_hellman_t public;

	/**
	 * Diffie Hellman group number.
	 */
	key_exchange_method_t group;

	/**
	 * EC private (public) key
	 */
	EVP_PKEY *key;

	/**
	 * EC group
	 */
	EC_GROUP *ec_group;

	/**
	 * Shared secret
	 */
	chunk_t shared_secret;

	/**
	 * True if shared secret is computed
	 */
	bool computed;
};

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
/**
 * Convert a chunk to an EC_POINT and set it on the given key. The x and y
 * coordinates of the point have to be concatenated in the chunk.
 */
static bool chunk2ecp(const EC_GROUP *group, chunk_t chunk, EVP_PKEY *key)
{
	EC_POINT *point = NULL;
	EC_KEY *pub = NULL;
	BN_CTX *ctx;
	BIGNUM *x, *y;
	bool ret = FALSE;

	ctx = BN_CTX_new();
	if (!ctx)
	{
		return FALSE;
	}

	BN_CTX_start(ctx);
	x = BN_CTX_get(ctx);
	y = BN_CTX_get(ctx);
	if (!x || !y)
	{
		goto error;
	}

	if (!openssl_bn_split(chunk, x, y))
	{
		goto error;
	}

	point = EC_POINT_new(group);
	if (!point || !EC_POINT_set_affine_coordinates_GFp(group, point, x, y, ctx))
	{
		goto error;
	}

	if (!EC_POINT_is_on_curve(group, point, ctx))
	{
		goto error;
	}

	pub = EC_KEY_new();
	if (!pub || !EC_KEY_set_group(pub, group))
	{
		goto error;
	}

	if (EC_KEY_set_public_key(pub, point) != 1)
	{
		goto error;
	}

	if (EVP_PKEY_set1_EC_KEY(key, pub) != 1)
	{
		goto error;
	}

	ret = TRUE;

error:
	EC_POINT_clear_free(point);
	EC_KEY_free(pub);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return ret;
}

/**
 * Convert a key to a chunk by concatenating the x and y coordinates of
 * the underlying EC point. This function allocates memory for the chunk.
 */
static bool ecp2chunk(const EC_GROUP *group, EVP_PKEY *key, chunk_t *chunk)
{
	EC_KEY *ec_key = NULL;
	const EC_POINT *point;
	BN_CTX *ctx;
	BIGNUM *x, *y;
	bool ret = FALSE;

	ctx = BN_CTX_new();
	if (!ctx)
	{
		return FALSE;
	}

	BN_CTX_start(ctx);
	x = BN_CTX_get(ctx);
	y = BN_CTX_get(ctx);
	if (!x || !y)
	{
		goto error;
	}

	ec_key = EVP_PKEY_get1_EC_KEY(key);
	point = EC_KEY_get0_public_key(ec_key);
	if (!point || !EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx))
	{
		goto error;
	}

	if (!openssl_bn_cat(EC_FIELD_ELEMENT_LEN(group), x, y, chunk))
	{
		goto error;
	}

	ret = chunk->len != 0;
error:
	EC_KEY_free(ec_key);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return ret;
}
#endif /* OPENSSL_VERSION_NUMBER < ... */

METHOD(key_exchange_t, set_public_key, bool,
	private_openssl_ec_diffie_hellman_t *this, chunk_t value)
{
	EVP_PKEY *pub = NULL;

	chunk_clear(&this->shared_secret);
	this->computed = FALSE;

	if (!key_exchange_verify_pubkey(this->group, value))
	{
		return FALSE;
	}

	pub = EVP_PKEY_new();
	if (!pub)
	{
		goto error;
	}

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	if (!chunk2ecp(this->ec_group, value, pub))
	{
		DBG1(DBG_LIB, "ECDH public value is malformed");
		goto error;
	}
#else
	/* OpenSSL expects the pubkey in the format specified in section 2.3.4 of
	 * SECG SEC 1, i.e. prefixed with 0x04 to indicate an uncompressed point */
	value = chunk_cata("cc", chunk_from_chars(0x04), value);
	if (EVP_PKEY_copy_parameters(pub, this->key) <= 0 ||
		EVP_PKEY_set1_tls_encodedpoint(pub, value.ptr, value.len) <= 0)
	{
		DBG1(DBG_LIB, "ECDH public value is malformed");
		goto error;
	}
#endif

	if (!openssl_compute_shared_key(this->key, pub, &this->shared_secret))
	{
		DBG1(DBG_LIB, "ECDH shared secret computation failed");
		goto error;
	}
	this->computed = TRUE;

error:
	EVP_PKEY_free(pub);
	return this->computed;
}

METHOD(key_exchange_t, get_public_key, bool,
	private_openssl_ec_diffie_hellman_t *this, chunk_t *value)
{
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	return ecp2chunk(this->ec_group, this->key, value);
#else
	chunk_t pub;

	/* OpenSSL returns the pubkey in the format specified in section 2.3.4 of
	 * SECG SEC 1, i.e. prefixed with 0x04 to indicate an uncompressed point */
	pub.len = EVP_PKEY_get1_tls_encodedpoint(this->key, &pub.ptr);
	if (pub.len != 0)
	{
		*value = chunk_clone(chunk_skip(pub, 1));
		OPENSSL_free(pub.ptr);
		return value->len != 0;
	}
	return FALSE;
#endif
}

METHOD(key_exchange_t, set_seed, bool,
	private_openssl_ec_diffie_hellman_t *this, chunk_t value, drbg_t *drbg)
{
	EC_KEY *key = NULL;
	EC_POINT *pub = NULL;
	BIGNUM *priv = NULL;
	bool ret = FALSE;

	priv = BN_bin2bn(value.ptr, value.len, NULL);
	if (!priv)
	{
		goto error;
	}
	pub = EC_POINT_new(this->ec_group);
	if (!pub)
	{
		goto error;
	}
	if (EC_POINT_mul(this->ec_group, pub, priv, NULL, NULL, NULL) != 1)
	{
		goto error;
	}
	key = EC_KEY_new();
	if (!key || !EC_KEY_set_group(key, this->ec_group))
	{
		goto error;
	}
	if (EC_KEY_set_private_key(key, priv) != 1)
	{
		goto error;
	}
	if (EC_KEY_set_public_key(key, pub) != 1)
	{
		goto error;
	}
	if (EVP_PKEY_set1_EC_KEY(this->key, key) != 1)
	{
		goto error;
	}
	ret = TRUE;

error:
	EC_POINT_free(pub);
	BN_free(priv);
	EC_KEY_free(key);
	return ret;
}

METHOD(key_exchange_t, get_shared_secret, bool,
	private_openssl_ec_diffie_hellman_t *this, chunk_t *secret)
{
	if (!this->computed)
	{
		return FALSE;
	}
	*secret = chunk_clone(this->shared_secret);
	return TRUE;
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
	private_openssl_ec_diffie_hellman_t *this)
{
	return this->group;
}

METHOD(key_exchange_t, destroy, void,
	private_openssl_ec_diffie_hellman_t *this)
{
	EC_GROUP_free(this->ec_group);
	EVP_PKEY_free(this->key);
	chunk_clear(&this->shared_secret);
	free(this);
}

/*
 * Described in header
 */
int openssl_ecdh_group_to_nid(key_exchange_method_t group)
{
	switch (group)
	{
		case ECP_192_BIT:
			return NID_X9_62_prime192v1;
		case ECP_224_BIT:
			return NID_secp224r1;
		case ECP_256_BIT:
			return NID_X9_62_prime256v1;
		case ECP_384_BIT:
			return NID_secp384r1;
		case ECP_521_BIT:
			return NID_secp521r1;
/* added with 1.0.2 */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
		case ECP_224_BP:
			return NID_brainpoolP224r1;
		case ECP_256_BP:
			return NID_brainpoolP256r1;
		case ECP_384_BP:
			return NID_brainpoolP384r1;
		case ECP_512_BP:
			return NID_brainpoolP512r1;
#endif
		default:
			return 0;
	}
}

/*
 * Described in header
 */
openssl_ec_diffie_hellman_t *openssl_ec_diffie_hellman_create(key_exchange_method_t group)
{
	private_openssl_ec_diffie_hellman_t *this;
	EC_KEY *key = NULL;
	int curve;

	curve = openssl_ecdh_group_to_nid(group);
	if (curve)
	{
		key = EC_KEY_new_by_curve_name(curve);
	}
	if (!key)
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.ke = {
				.get_shared_secret = _get_shared_secret,
				.set_public_key = _set_public_key,
				.get_public_key = _get_public_key,
				.set_seed = _set_seed,
				.get_method = _get_method,
				.destroy = _destroy,
			},
		},
		.group = group,
		.ec_group = EC_GROUP_dup(EC_KEY_get0_group(key)),
	);

	/* generate an EC private (public) key */
	if (!EC_KEY_generate_key(key))
	{
		EC_KEY_free(key);
		destroy(this);
		return NULL;
	}

	this->key = EVP_PKEY_new();
	if (!this->key || !EVP_PKEY_assign_EC_KEY(this->key, key))
	{
		EC_KEY_free(key);
		destroy(this);
		return NULL;
	}
	return &this->public;
}

#endif /* OPENSSL_NO_EC */
