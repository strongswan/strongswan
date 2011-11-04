/*
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

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_EC

#include <openssl/ec.h>
#include <openssl/objects.h>

#include "openssl_ec_diffie_hellman.h"
#include "openssl_util.h"

#include <debug.h>

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
	u_int16_t group;

	/**
	 * EC private (public) key
	 */
	EC_KEY *key;

	/**
	 * EC group
	 */
	const EC_GROUP *ec_group;

	/**
	 * Other public key
	 */
	EC_POINT *pub_key;

	/**
	 * Shared secret
	 */
	chunk_t shared_secret;

	/**
	 * True if shared secret is computed
	 */
	bool computed;
};

/**
 * Convert a chunk to an EC_POINT (which must already exist). The x and y
 * coordinates of the point have to be concatenated in the chunk.
 */
static bool chunk2ecp(const EC_GROUP *group, chunk_t chunk, EC_POINT *point)
{
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

	if (!EC_POINT_set_affine_coordinates_GFp(group, point, x, y, ctx))
	{
		goto error;
	}

	ret = TRUE;
error:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return ret;
}

/**
 * Convert an EC_POINT to a chunk by concatenating the x and y coordinates of
 * the point. This function allocates memory for the chunk.
 */
static bool ecp2chunk(const EC_GROUP *group, const EC_POINT *point,
					  chunk_t *chunk, bool x_coordinate_only)
{
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

	if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx))
	{
		goto error;
	}

	if (x_coordinate_only)
	{
		y = NULL;
	}
	if (!openssl_bn_cat(EC_FIELD_ELEMENT_LEN(group), x, y, chunk))
	{
		goto error;
	}

	ret = TRUE;
error:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return ret;
}

/**
 * Compute the shared secret.
 *
 * We cannot use the function ECDH_compute_key() because that returns only the
 * x coordinate of the shared secret point (which is defined, for instance, in
 * 'NIST SP 800-56A').
 * However, we need both coordinates as RFC 4753 says: "The Diffie-Hellman
 *   public value is obtained by concatenating the x and y values. The format
 *   of the Diffie-Hellman shared secret value is the same as that of the
 *   Diffie-Hellman public value."
 */
static bool compute_shared_key(private_openssl_ec_diffie_hellman_t *this,
							   chunk_t *shared_secret)
{
	const BIGNUM *priv_key;
	EC_POINT *secret = NULL;
	bool x_coordinate_only, ret = FALSE;

	priv_key = EC_KEY_get0_private_key(this->key);
	if (!priv_key)
	{
		goto error;
	}

	secret = EC_POINT_new(this->ec_group);
	if (!secret)
	{
		goto error;
	}

	if (!EC_POINT_mul(this->ec_group, secret, NULL, this->pub_key, priv_key, NULL))
	{
		goto error;
	}

	/*
	 * The default setting ecp_x_coordinate_only = TRUE
	 * applies the following errata for RFC 4753:
	 * http://www.rfc-editor.org/errata_search.php?eid=9
	 */
	x_coordinate_only = lib->settings->get_bool(lib->settings,
							"libstrongswan.ecp_x_coordinate_only", TRUE);
	if (!ecp2chunk(this->ec_group, secret, shared_secret, x_coordinate_only))
	{
		goto error;
	}

	ret = TRUE;
error:
	if (secret)
	{
		EC_POINT_clear_free(secret);
	}
	return ret;
}

METHOD(diffie_hellman_t, set_other_public_value, void,
	private_openssl_ec_diffie_hellman_t *this, chunk_t value)
{
	if (!chunk2ecp(this->ec_group, value, this->pub_key))
	{
		DBG1(DBG_LIB, "ECDH public value is malformed");
		return;
	}

	chunk_clear(&this->shared_secret);

	if (!compute_shared_key(this, &this->shared_secret)) {
		DBG1(DBG_LIB, "ECDH shared secret computation failed");
		return;
	}

	this->computed = TRUE;
}

METHOD(diffie_hellman_t, get_my_public_value, void,
	private_openssl_ec_diffie_hellman_t *this,chunk_t *value)
{
	ecp2chunk(this->ec_group, EC_KEY_get0_public_key(this->key), value, FALSE);
}

METHOD(diffie_hellman_t, get_shared_secret, status_t,
	private_openssl_ec_diffie_hellman_t *this, chunk_t *secret)
{
	if (!this->computed)
	{
		return FAILED;
	}
	*secret = chunk_clone(this->shared_secret);
	return SUCCESS;
}

METHOD(diffie_hellman_t, get_dh_group, diffie_hellman_group_t,
	private_openssl_ec_diffie_hellman_t *this)
{
	return this->group;
}

METHOD(diffie_hellman_t, destroy, void,
	private_openssl_ec_diffie_hellman_t *this)
{
	EC_POINT_clear_free(this->pub_key);
	EC_KEY_free(this->key);
	chunk_clear(&this->shared_secret);
	free(this);
}

/*
 * Described in header.
 */
openssl_ec_diffie_hellman_t *openssl_ec_diffie_hellman_create(diffie_hellman_group_t group)
{
	private_openssl_ec_diffie_hellman_t *this;

	INIT(this,
		.public = {
			.dh = {
				.get_shared_secret = _get_shared_secret,
				.set_other_public_value = _set_other_public_value,
				.get_my_public_value = _get_my_public_value,
				.get_dh_group = _get_dh_group,
				.destroy = _destroy,
			},
		},
		.group = group,
	);

	switch (group)
	{
		case ECP_192_BIT:
			this->key = EC_KEY_new_by_curve_name(NID_X9_62_prime192v1);
			break;
		case ECP_224_BIT:
			this->key = EC_KEY_new_by_curve_name(NID_secp224r1);
			break;
		case ECP_256_BIT:
			this->key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
			break;
		case ECP_384_BIT:
			this->key = EC_KEY_new_by_curve_name(NID_secp384r1);
			break;
		case ECP_521_BIT:
			this->key = EC_KEY_new_by_curve_name(NID_secp521r1);
			break;
		default:
			this->key = NULL;
			break;
	}

	if (!this->key)
	{
		free(this);
		return NULL;
	}

	/* caching the EC group */
	this->ec_group = EC_KEY_get0_group(this->key);

	this->pub_key = EC_POINT_new(this->ec_group);
	if (!this->pub_key)
	{
		free(this);
		return NULL;
	}

	/* generate an EC private (public) key */
	if (!EC_KEY_generate_key(this->key))
	{
		free(this);
		return NULL;
	}

	return &this->public;
}
#endif /* OPENSSL_NO_EC */

