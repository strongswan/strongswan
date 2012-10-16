/*
 * Copyright (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
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

#include <utils/debug.h>
#include <tkm/constants.h>
#include <tkm/client.h>

#include "tkm_utils.h"
#include "tkm_types.h"
#include "tkm_private_key.h"

typedef struct private_tkm_private_key_t private_tkm_private_key_t;

/**
 * Private data of a tkm_private_key_t object.
 */
struct private_tkm_private_key_t {

	/**
	 * Public interface for this signer.
	 */
	tkm_private_key_t public;

	/**
	 * Key fingerprint.
	 */
	chunk_t fingerprint;

	/**
	 * Reference count.
	 */
	refcount_t ref;

};

METHOD(private_key_t, get_type, key_type_t,
	private_tkm_private_key_t *this)
{
	return KEY_RSA;
}

METHOD(private_key_t, sign, bool,
	private_tkm_private_key_t *this, signature_scheme_t scheme,
	chunk_t data, chunk_t *signature)
{
	signature_type sig;
	init_message_type msg;

	if (data.ptr == NULL)
	{
		DBG1(DBG_LIB, "unable to get signature information");
		return FALSE;
	}
	sign_info_t sign = *(sign_info_t *)(data.ptr);

	chunk_to_sequence(&sign.init_message, &msg, sizeof(init_message_type));
	const isa_id_type isa_id = sign.isa_id;
	chunk_free(&sign.init_message);

	if (ike_isa_sign(isa_id, 1, msg, &sig) != TKM_OK)
	{
		DBG1(DBG_LIB, "signature operation failed");
		return FALSE;
	}

	sequence_to_chunk(sig.data, sig.size, signature);
	return TRUE;
}

METHOD(private_key_t, decrypt, bool,
	private_tkm_private_key_t *this, encryption_scheme_t scheme,
	chunk_t crypto, chunk_t *plain)
{
	return FALSE;
}

METHOD(private_key_t, get_keysize, int,
	private_tkm_private_key_t *this)
{
	return 0;
}

METHOD(private_key_t, get_public_key, public_key_t*,
	private_tkm_private_key_t *this)
{
	return NULL;
}

METHOD(private_key_t, get_encoding, bool,
	private_tkm_private_key_t *this, cred_encoding_type_t type,
	chunk_t *encoding)
{
	return FALSE;
}

METHOD(private_key_t, get_fingerprint, bool,
	private_tkm_private_key_t *this, cred_encoding_type_t type, chunk_t *fp)
{
	*fp = this->fingerprint;
	return TRUE;
}

METHOD(private_key_t, get_ref, private_key_t*,
	private_tkm_private_key_t *this)
{
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(private_key_t, destroy, void,
	private_tkm_private_key_t *this)
{
	if (ref_put(&this->ref))
	{
		chunk_free(&this->fingerprint);
		free(this);
	}
}

/**
 * See header.
 */
tkm_private_key_t *tkm_private_key_init(void)
{
	private_tkm_private_key_t *this;

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

	/* fingerprint of alice@strongswan.org keypair */
	const char fake_fp[] = "05da04208c02f428470acf6c772d066613da863c";
	this->fingerprint = chunk_create((u_char *)fake_fp, strlen(fake_fp));
	this->fingerprint = chunk_from_hex(this->fingerprint, NULL);

	return &this->public;
}
