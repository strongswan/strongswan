/*
 * Copyright (C) 2018 René Korthaus
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

#include "botan_ec_diffie_hellman.h"

#include <botan/build.h>

#ifdef BOTAN_HAS_ECDH

#include <utils/debug.h>

#include <botan/ffi.h>

typedef struct private_botan_ec_diffie_hellman_t
	private_botan_ec_diffie_hellman_t;

/**
 * Private data of a botan_ec_diffie_hellman_t object.
 */
struct private_botan_ec_diffie_hellman_t {
	/**
	 * Public botan_ec_diffie_hellman_t interface
	 */
	botan_ec_diffie_hellman_t public;

	/**
	 * Diffie Hellman group
	 */
	diffie_hellman_group_t group;

	/**
	 * EC curve name
	 */
	const char* curve_name;

	/**
	 * EC private key
	 */
	botan_privkey_t key;

	/**
	 * Shared secret
	 */
	chunk_t shared_secret;

	/**
	 * True if shared secret is computed
	 */
	bool computed;
};

METHOD(diffie_hellman_t, set_other_public_value, bool,
	private_botan_ec_diffie_hellman_t *this, chunk_t value)
{
	if (!diffie_hellman_verify_value(this->group, value))
	{
		return FALSE;
	}

	botan_pk_op_ka_t ka;
	if (botan_pk_op_key_agreement_create(&ka, this->key, "Raw", 0))
	{
		return FALSE;
	}

	/* prepend 0x04 to indicate uncompressed point format */
	uint8_t indic = 0x04;
	value = chunk_cata("cc", chunk_from_thing(indic), value);
	size_t out_len = 0;
	if (botan_pk_op_key_agreement(ka, NULL, &out_len, value.ptr, value.len,
								  NULL, 0)
		!= BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE)
	{
		botan_pk_op_key_agreement_destroy(ka);
		return FALSE;
	}

	if (out_len == 0)
	{
		botan_pk_op_key_agreement_destroy(ka);
		return FALSE;
	}

	chunk_clear(&this->shared_secret);
	this->shared_secret = chunk_alloc(out_len);
	if (botan_pk_op_key_agreement(ka, this->shared_secret.ptr,
								  &this->shared_secret.len, value.ptr,
								  value.len, NULL, 0))
	{
		chunk_clear(&this->shared_secret);
		botan_pk_op_key_agreement_destroy(ka);
		return FALSE;
	}

	botan_pk_op_key_agreement_destroy(ka);
	this->computed = TRUE;
	return TRUE;
}

METHOD(diffie_hellman_t, get_my_public_value, bool,
	private_botan_ec_diffie_hellman_t *this, chunk_t *value)
{
	chunk_t pkey = chunk_empty;
	if (botan_pk_op_key_agreement_export_public(this->key, NULL, &pkey.len)
		!= BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE)
	{
		return FALSE;
	}

	pkey = chunk_alloca(pkey.len);
	if (botan_pk_op_key_agreement_export_public(this->key, pkey.ptr, &pkey.len))
	{
		return FALSE;
	}

	/* skip 0x04 byte prepended by botan */
	*value = chunk_clone(chunk_skip(pkey, 1));
	return TRUE;
}

METHOD(diffie_hellman_t, set_private_value, bool,
	private_botan_ec_diffie_hellman_t *this, chunk_t value)
{
	botan_mp_t scalar;
	if (botan_mp_init(&scalar))
	{
		return FALSE;
	}

	if (botan_mp_from_bin(scalar, value.ptr, value.len))
	{
		botan_mp_destroy(scalar);
		return FALSE;
	}

	if (botan_privkey_destroy(this->key))
	{
		botan_mp_destroy(scalar);
		return FALSE;
	}

	if (botan_privkey_load_ecdh(&this->key, scalar, this->curve_name))
	{
		botan_mp_destroy(scalar);
		return FALSE;
	}

	botan_mp_destroy(scalar);
	this->computed = FALSE;
	return TRUE;
}

METHOD(diffie_hellman_t, get_shared_secret, bool,
	private_botan_ec_diffie_hellman_t *this, chunk_t *secret)
{
	if (!this->computed)
	{
		return FALSE;
	}
	*secret = chunk_clone(this->shared_secret);
	return TRUE;
}

METHOD(diffie_hellman_t, get_dh_group, diffie_hellman_group_t,
	private_botan_ec_diffie_hellman_t *this)
{
	return this->group;
}

METHOD(diffie_hellman_t, destroy, void,
	private_botan_ec_diffie_hellman_t *this)
{
	botan_privkey_destroy(this->key);
	chunk_clear(&this->shared_secret);
	free(this);
}

/*
 * Described in header.
 */
botan_ec_diffie_hellman_t *
botan_ec_diffie_hellman_create(diffie_hellman_group_t group)
{
	private_botan_ec_diffie_hellman_t *this;

	INIT(this,
		.public = {
			.dh = {
				.get_shared_secret = _get_shared_secret,
				.set_other_public_value = _set_other_public_value,
				.get_my_public_value = _get_my_public_value,
				.set_private_value = _set_private_value,
				.get_dh_group = _get_dh_group,
				.destroy = _destroy,
			},
		},
		.group = group,
	);

	switch (group)
	{
		case ECP_256_BIT:
			this->curve_name = "secp256r1";
			break;
		case ECP_384_BIT:
			this->curve_name = "secp384r1";
			break;
		case ECP_521_BIT:
			this->curve_name = "secp521r1";
			break;
		case ECP_256_BP:
			this->curve_name = "brainpool256r1";
			break;
		case ECP_384_BP:
			this->curve_name = "brainpool384r1";
			break;
		case ECP_512_BP:
			this->curve_name = "brainpool512r1";
			break;
		default:
			free(this);
			return NULL;
	}

	return &this->public;
}

#endif
