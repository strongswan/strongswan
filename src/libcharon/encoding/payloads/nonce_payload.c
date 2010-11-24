/*
 * Copyright (C) 2005-2010 Martin Willi
 * Copyright (C) 2010 revosec AG
 * Copyright (C) 2005 Jan Hutter
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

#include <stddef.h>

#include "nonce_payload.h"

#include <encoding/payloads/encodings.h>

typedef struct private_nonce_payload_t private_nonce_payload_t;

/**
 * Private data of an nonce_payload_t object.
 */
struct private_nonce_payload_t {

	/**
	 * Public nonce_payload_t interface.
	 */
	nonce_payload_t public;

	/**
	 * Next payload type.
	 */
	u_int8_t  next_payload;

	/**
	 * Critical flag.
	 */
	bool critical;

	/**
	 * Reserved bits
	 */
	bool reserved[7];

	/**
	 * Length of this payload.
	 */
	u_int16_t payload_length;

	/**
	 * The contained nonce value.
	 */
	chunk_t nonce;
};

/**
 * Encoding rules to parse or generate a nonce payload
 *
 * The defined offsets are the positions in a object of type
 * private_nonce_payload_t.
 */
encoding_rule_t nonce_payload_encodings[] = {
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_nonce_payload_t, next_payload)		},
	/* the critical bit */
	{ FLAG,				offsetof(private_nonce_payload_t, critical)			},
	/* 7 Bit reserved bits */
	{ RESERVED_BIT,		offsetof(private_nonce_payload_t, reserved[0])		},
	{ RESERVED_BIT,		offsetof(private_nonce_payload_t, reserved[1])		},
	{ RESERVED_BIT,		offsetof(private_nonce_payload_t, reserved[2])		},
	{ RESERVED_BIT,		offsetof(private_nonce_payload_t, reserved[3])		},
	{ RESERVED_BIT,		offsetof(private_nonce_payload_t, reserved[4])		},
	{ RESERVED_BIT,		offsetof(private_nonce_payload_t, reserved[5])		},
	{ RESERVED_BIT,		offsetof(private_nonce_payload_t, reserved[6])		},
	/* Length of the whole nonce payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_nonce_payload_t, payload_length)	},
	/* some nonce bytes, lenth is defined in PAYLOAD_LENGTH */
	{ NONCE_DATA,		offsetof(private_nonce_payload_t, nonce)			},
};

/*                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                            Nonce Data                         ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

METHOD(payload_t, verify, status_t,
	private_nonce_payload_t *this)
{
	if (this->nonce.len < 16 || this->nonce.len > 256)
	{
		return FAILED;
	}
	return SUCCESS;
}

METHOD(payload_t, get_encoding_rules, void,
	private_nonce_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = nonce_payload_encodings;
	*rule_count = countof(nonce_payload_encodings);
}

METHOD(payload_t, get_type, payload_type_t,
	private_nonce_payload_t *this)
{
	return NONCE;
}

METHOD(payload_t, get_next_type, payload_type_t,
	private_nonce_payload_t *this)
{
	return this->next_payload;
}

METHOD(payload_t, set_next_type, void,
	private_nonce_payload_t *this, payload_type_t type)
{
	this->next_payload = type;
}

METHOD(payload_t, get_length, size_t,
	private_nonce_payload_t *this)
{
	return this->payload_length;
}

METHOD(nonce_payload_t, set_nonce, void,
	 private_nonce_payload_t *this, chunk_t nonce)
{
	this->nonce = chunk_clone(nonce);
	this->payload_length = NONCE_PAYLOAD_HEADER_LENGTH + nonce.len;
}

METHOD(nonce_payload_t, get_nonce, chunk_t,
	private_nonce_payload_t *this)
{
	return chunk_clone(this->nonce);
}

METHOD2(payload_t, nonce_payload_t, destroy, void,
	private_nonce_payload_t *this)
{
	free(this->nonce.ptr);
	free(this);
}

/*
 * Described in header
 */
nonce_payload_t *nonce_payload_create()
{
	private_nonce_payload_t *this;

	INIT(this,
		.public = {
			.payload_interface = {
				.verify = _verify,
				.get_encoding_rules = _get_encoding_rules,
				.get_length = _get_length,
				.get_next_type = _get_next_type,
				.set_next_type = _set_next_type,
				.get_type = _get_type,
				.destroy = _destroy,
			},
			.set_nonce = _set_nonce,
			.get_nonce = _get_nonce,
			.destroy = _destroy,
		},
		.next_payload = NO_PAYLOAD,
		.payload_length = NONCE_PAYLOAD_HEADER_LENGTH,
	);
	return &this->public;
}
