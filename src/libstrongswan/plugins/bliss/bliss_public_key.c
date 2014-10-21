/*
 * Copyright (C) 2014 Andreas Steffen
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

#include "bliss_public_key.h"

typedef struct private_bliss_public_key_t private_bliss_public_key_t;

/**
 * Private data structure with signing context.
 */
struct private_bliss_public_key_t {
	/**
	 * Public interface for this signer.
	 */
	bliss_public_key_t public;

	/**
	 * BLISS type
	 */
	u_int key_size;

	/**
	 * reference counter
	 */
	refcount_t ref;
};

METHOD(public_key_t, get_type, key_type_t,
	private_bliss_public_key_t *this)
{
	return KEY_BLISS;
}

METHOD(public_key_t, verify, bool,
	private_bliss_public_key_t *this, signature_scheme_t scheme,
	chunk_t data, chunk_t signature)
{
	switch (scheme)
	{
		case SIGN_BLISS_I_SHA256:
			return FALSE;
		case SIGN_BLISS_IV_SHA384:
			return FALSE;
		default:
			DBG1(DBG_LIB, "signature scheme %N not supported by BLISS",
				 signature_scheme_names, scheme);
			return FALSE;
	}
}

METHOD(public_key_t, encrypt_, bool,
	private_bliss_public_key_t *this, encryption_scheme_t scheme,
	chunk_t plain, chunk_t *crypto)
{
	DBG1(DBG_LIB, "encryption scheme %N not supported",
				   encryption_scheme_names, scheme);
	return FALSE;
}

METHOD(public_key_t, get_keysize, int,
	private_bliss_public_key_t *this)
{
	return this->key_size;
}

METHOD(public_key_t, get_encoding, bool,
	private_bliss_public_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	bool success = TRUE;

	*encoding = chunk_empty;

	return success;
}

METHOD(public_key_t, get_fingerprint, bool,
	private_bliss_public_key_t *this, cred_encoding_type_t type, chunk_t *fp)
{
	bool success = FALSE;

	return success;
}

METHOD(public_key_t, get_ref, public_key_t*,
	private_bliss_public_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(public_key_t, destroy, void,
	private_bliss_public_key_t *this)
{
	if (ref_put(&this->ref))
	{
		free(this);
	}
}

/**
 * See header.
 */
bliss_public_key_t *bliss_public_key_load(key_type_t type, va_list args)
{
	private_bliss_public_key_t *this;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	INIT(this,
		.public = {
			.key = {
				.get_type = _get_type,
				.verify = _verify,
				.encrypt = _encrypt_,
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

	return &this->public;
}
