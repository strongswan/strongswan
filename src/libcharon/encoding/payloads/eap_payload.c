/*
 * Copyright (C) 2005-2010 Martin Willi
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

#include "eap_payload.h"

#include <daemon.h>

typedef struct private_eap_payload_t private_eap_payload_t;

/**
 * Private data of an eap_payload_t object.
 *
 */
struct private_eap_payload_t {
	/**
	 * Public eap_payload_t interface.
	 */
	eap_payload_t public;

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
	 * EAP message data, if available
	 */
	chunk_t data;
};

/**
 * Encoding rules to parse or generate a EAP payload.
 *
 * The defined offsets are the positions in a object of type
 * private_eap_payload_t.
 *
 */
static encoding_rule_t eap_payload_encodings[] = {
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_eap_payload_t, next_payload) 	},
	/* the critical bit */
	{ FLAG,				offsetof(private_eap_payload_t, critical) 		},
	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,		offsetof(private_eap_payload_t, reserved[0])	},
	{ RESERVED_BIT,		offsetof(private_eap_payload_t, reserved[1])	},
	{ RESERVED_BIT,		offsetof(private_eap_payload_t, reserved[2])	},
	{ RESERVED_BIT,		offsetof(private_eap_payload_t, reserved[3])	},
	{ RESERVED_BIT,		offsetof(private_eap_payload_t, reserved[4])	},
	{ RESERVED_BIT,		offsetof(private_eap_payload_t, reserved[5])	},
	{ RESERVED_BIT,		offsetof(private_eap_payload_t, reserved[6])	},
	/* Length of the whole payload*/
	{ PAYLOAD_LENGTH,	offsetof(private_eap_payload_t, payload_length)	},
	/* chunt to data, starting at "code" */
	{ EAP_DATA,			offsetof(private_eap_payload_t, data)			},
};

/*
                            1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ! Next Payload  !C!  RESERVED   !         Payload Length        !
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       !     Code      ! Identifier    !           Length              !
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       !     Type      ! Type_Data...
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
*/

METHOD(payload_t, verify, status_t,
	private_eap_payload_t *this)
{
	u_int16_t length;
	u_int8_t code;

	if (this->data.len < 4)
	{
		DBG1(DBG_ENC, "EAP payloads EAP message too short (%d)", this->data.len);
		return FAILED;
	}
	length = untoh16(this->data.ptr + 2);
	if (this->data.len != length)
	{
		DBG1(DBG_ENC, "EAP payload length (%d) does not match contained "
			 "message length (%d)", this->data.len, length);
		return FAILED;
	}
	code = this->data.ptr[0];
	switch (code)
	{
		case EAP_REQUEST:
		case EAP_RESPONSE:
		{
			if (this->data.len < 4)
			{
				DBG1(DBG_ENC, "EAP Request/Response does not have any data");
				return FAILED;
			}
			break;
		}
		case EAP_SUCCESS:
		case EAP_FAILURE:
		{
			if (this->data.len != 4)
			{
				DBG1(DBG_ENC, "EAP Success/Failure has data");
				return FAILED;
			}
			break;
		}
		default:
			return FAILED;
	}
	return SUCCESS;
}

METHOD(payload_t, get_encoding_rules, void,
	private_eap_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = eap_payload_encodings;
	*rule_count = sizeof(eap_payload_encodings) / sizeof(encoding_rule_t);
}

METHOD(payload_t, get_payload_type, payload_type_t,
	private_eap_payload_t *this)
{
	return EXTENSIBLE_AUTHENTICATION;
}

METHOD(payload_t, get_next_type, payload_type_t,
	private_eap_payload_t *this)
{
	return (this->next_payload);
}

METHOD(payload_t, set_next_type, void,
	private_eap_payload_t *this, payload_type_t type)
{
	this->next_payload = type;
}

METHOD(payload_t, get_length, size_t,
	private_eap_payload_t *this)
{
	return this->payload_length;
}

METHOD(eap_payload_t, get_data, chunk_t,
	private_eap_payload_t *this)
{
	return this->data;
}

METHOD(eap_payload_t, set_data, void,
	private_eap_payload_t *this, chunk_t data)
{
	free(this->data.ptr);
	this->data = chunk_clone(data);
	this->payload_length = this->data.len + 4;
}

METHOD(eap_payload_t, get_code, eap_code_t,
	private_eap_payload_t *this)
{
	if (this->data.len > 0)
	{
		return this->data.ptr[0];
	}
	/* should not happen, as it is verified */
	return 0;
}

METHOD(eap_payload_t, get_identifier, u_int8_t,
	private_eap_payload_t *this)
{
	if (this->data.len > 1)
	{
		return this->data.ptr[1];
	}
	/* should not happen, as it is verified */
	return 0;
}

METHOD(eap_payload_t, get_type, eap_type_t,
	private_eap_payload_t *this, u_int32_t *vendor)
{
	eap_type_t type;

	*vendor = 0;
	if (this->data.len > 4)
	{
		type = this->data.ptr[4];
		if (type != EAP_EXPANDED)
		{
			return type;
		}
		if (this->data.len >= 12)
		{
			*vendor = untoh32(this->data.ptr + 4) & 0x00FFFFFF;
			return untoh32(this->data.ptr + 8);
		}
	}
	return 0;
}

METHOD2(payload_t, eap_payload_t, destroy, void,
	private_eap_payload_t *this)
{
	chunk_free(&this->data);
	free(this);
}

/*
 * Described in header
 */
eap_payload_t *eap_payload_create()
{
	private_eap_payload_t *this;

	INIT(this,
		.public = {
			.payload_interface = {
				.verify = _verify,
				.get_encoding_rules = _get_encoding_rules,
				.get_length = _get_length,
				.get_next_type = _get_next_type,
				.set_next_type = _set_next_type,
				.get_type = _get_payload_type,
				.destroy = _destroy,
			},
			.get_data = _get_data,
			.set_data = _set_data,
			.get_code = _get_code,
			.get_identifier = _get_identifier,
			.get_type = _get_type,
			.destroy = _destroy,
		},
		.next_payload = NO_PAYLOAD,
		.payload_length = EAP_PAYLOAD_HEADER_LENGTH,
	);
	return &this->public;
}

/*
 * Described in header
 */
eap_payload_t *eap_payload_create_data(chunk_t data)
{
	eap_payload_t *this = eap_payload_create();

	this->set_data(this, data);
	return this;
}

/*
 * Described in header
 */
eap_payload_t *eap_payload_create_data_own(chunk_t data)
{
	eap_payload_t *this = eap_payload_create();

	this->set_data(this, data);
	free(data.ptr);
	return this;
}

/*
 * Described in header
 */
eap_payload_t *eap_payload_create_code(eap_code_t code, u_int8_t identifier)
{
	chunk_t data;

	data = chunk_from_chars(code, identifier, 0, 0);
	htoun16(data.ptr + 2, data.len);
	return eap_payload_create_data(data);
}

/*
 * Described in header
 */
eap_payload_t *eap_payload_create_nak(u_int8_t identifier)
{
	chunk_t data;

	data = chunk_from_chars(EAP_RESPONSE, identifier, 0, 0, EAP_NAK);
	htoun16(data.ptr + 2, data.len);
	return eap_payload_create_data(data);
}

