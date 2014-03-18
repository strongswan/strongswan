/*
 * Copyright (C) 2014 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * Copyright (C) 2009-2013  Security Innovation
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

#include "ntru_public_key.h"

#include "ntru_crypto/ntru_crypto_ntru_convert.h"

#include <utils/debug.h>

typedef struct private_ntru_public_key_t private_ntru_public_key_t;

/**
 * Private data of an ntru_public_key_t object.
 */
struct private_ntru_public_key_t {
	/**
	 * Public ntru_public_key_t interface.
	 */
	ntru_public_key_t public;

	/**
	 * NTRU Parameter Set
	 */
	ntru_param_set_t *params;

	/**
	 * Polynomial h which is the public key
	 */
	uint16_t *pubkey;

	/**
	 * Encoding of the public key
	 */
	chunk_t encoding;

};

METHOD(ntru_public_key_t, get_encoding, chunk_t,
	private_ntru_public_key_t *this)
{
	if (!this->encoding.len)
	{
		size_t pubkey_len;
		u_char *enc;

		/* compute public key length encoded as packed coefficients */
		pubkey_len =  (this->params->N * this->params->q_bits + 7) / 8;

		/* allocate memory for public key encoding */
		this->encoding = chunk_alloc(2 + NTRU_OID_LEN + pubkey_len);
		enc = this->encoding.ptr;

		/* format header and packed public key */
		*enc++ = NTRU_PUBKEY_TAG;
		*enc++ = NTRU_OID_LEN;
		memcpy(enc, this->params->oid, NTRU_OID_LEN);
		enc += NTRU_OID_LEN;
		ntru_elements_2_octets(this->params->N, this->pubkey,
							   this->params->q_bits, enc);
	}
	return this->encoding;
}

METHOD(ntru_public_key_t, destroy, void,
	private_ntru_public_key_t *this)
{
	chunk_clear(&this->encoding);
	free(this->pubkey);
	free(this);
}

/*
 * Described in header.
 */
ntru_public_key_t *ntru_public_key_create(ntru_param_set_t *params,
										  uint16_t *pubkey)
{
	private_ntru_public_key_t *this;
	int i;

	INIT(this,
		.public = {
			.get_encoding = _get_encoding,
			.destroy = _destroy,
		},
		.params = params,
		.pubkey = malloc(params->N * sizeof(uint16_t)),
	);

	for (i = 0; i < params->N; i++)
	{
		this->pubkey[i] = pubkey[i];
	}

	return &this->public;
}
