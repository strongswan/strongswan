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

#include "cp_payload.h"

#include <encoding/payloads/encodings.h>
#include <utils/linked_list.h>

ENUM(config_type_names, CFG_REQUEST, CFG_ACK,
	"CFG_REQUEST",
	"CFG_REPLY",
	"CFG_SET",
	"CFG_ACK",
);

typedef struct private_cp_payload_t private_cp_payload_t;

/**
 * Private data of an cp_payload_t object.
 */
struct private_cp_payload_t {

	/**
	 * Public cp_payload_t interface.
	 */
	cp_payload_t public;

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
	bool reserved_bit[7];

	/**
	 * Reserved bytes
	 */
	u_int8_t reserved_byte[3];

	/**
	 * Length of this payload.
	 */
	u_int16_t payload_length;

	/**
	 * List of attributes, as configuration_attribute_t
	 */
	linked_list_t *attributes;

	/**
	 * Config Type.
	 */
	u_int8_t type;
};

/**
 * Encoding rules to parse or generate a IKEv2-CP Payload
 *
 * The defined offsets are the positions in a object of type
 * private_cp_payload_t.
 */
encoding_rule_t cp_payload_encodings[] = {
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,					offsetof(private_cp_payload_t, next_payload)	},
	/* the critical bit */
	{ FLAG,						offsetof(private_cp_payload_t, critical)		},
	/* 7 Bit reserved bits */
	{ RESERVED_BIT,				offsetof(private_cp_payload_t, reserved_bit[0])	},
	{ RESERVED_BIT,				offsetof(private_cp_payload_t, reserved_bit[1])	},
	{ RESERVED_BIT,				offsetof(private_cp_payload_t, reserved_bit[2])	},
	{ RESERVED_BIT,				offsetof(private_cp_payload_t, reserved_bit[3])	},
	{ RESERVED_BIT,				offsetof(private_cp_payload_t, reserved_bit[4])	},
	{ RESERVED_BIT,				offsetof(private_cp_payload_t, reserved_bit[5])	},
	{ RESERVED_BIT,				offsetof(private_cp_payload_t, reserved_bit[6])	},
	/* Length of the whole CP payload*/
	{ PAYLOAD_LENGTH,			offsetof(private_cp_payload_t, payload_length)	},
	/* Proposals are stored in a proposal substructure,
	   offset points to a linked_list_t pointer */
	{ U_INT_8,					offsetof(private_cp_payload_t, type)			},
	/* 3 reserved bytes */
	{ RESERVED_BYTE,			offsetof(private_cp_payload_t, reserved_byte[0])},
	{ RESERVED_BYTE,			offsetof(private_cp_payload_t, reserved_byte[1])},
	{ RESERVED_BYTE,			offsetof(private_cp_payload_t, reserved_byte[2])},
	{ CONFIGURATION_ATTRIBUTES,	offsetof(private_cp_payload_t, attributes)		}
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C! RESERVED    !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !   CFG Type    !                    RESERVED                   !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                   Configuration Attributes                    ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

METHOD(payload_t, verify, status_t,
	private_cp_payload_t *this)
{
	status_t status = SUCCESS;
	enumerator_t *enumerator;
	payload_t *attribute;

	enumerator = this->attributes->create_enumerator(this->attributes);
	while (enumerator->enumerate(enumerator, &attribute))
	{
		status = attribute->verify(attribute);
		if (status != SUCCESS)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	return status;
}

METHOD(payload_t, get_encoding_rules, void,
	private_cp_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = cp_payload_encodings;
	*rule_count = countof(cp_payload_encodings);
}

METHOD(payload_t, get_type, payload_type_t,
	private_cp_payload_t *this)
{
	return CONFIGURATION;
}

METHOD(payload_t, get_next_type, payload_type_t,
	private_cp_payload_t *this)
{
	return this->next_payload;
}

METHOD(payload_t, set_next_type, void,
	private_cp_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
}

/**
 * recompute the length of the payload.
 */
static void compute_length(private_cp_payload_t *this)
{
	enumerator_t *enumerator;
	payload_t *attribute;

	this->payload_length = CP_PAYLOAD_HEADER_LENGTH;

	enumerator = this->attributes->create_enumerator(this->attributes);
	while (enumerator->enumerate(enumerator, &attribute))
	{
		this->payload_length += attribute->get_length(attribute);
	}
	enumerator->destroy(enumerator);
}

METHOD(payload_t, get_length, size_t,
	private_cp_payload_t *this)
{
	return this->payload_length;
}

METHOD(cp_payload_t, create_attribute_enumerator, enumerator_t*,
	private_cp_payload_t *this)
{
	return this->attributes->create_enumerator(this->attributes);
}

METHOD(cp_payload_t, add_attribute, void,
	private_cp_payload_t *this, configuration_attribute_t *attribute)
{
	this->attributes->insert_last(this->attributes, attribute);
	compute_length(this);
}

METHOD(cp_payload_t, get_config_type, config_type_t,
	private_cp_payload_t *this)
{
	return this->type;
}

METHOD2(payload_t, cp_payload_t, destroy, void,
	private_cp_payload_t *this)
{
	this->attributes->destroy_offset(this->attributes,
								offsetof(configuration_attribute_t, destroy));
	free(this);
}

/*
 * Described in header.
 */
cp_payload_t *cp_payload_create_type(config_type_t type)
{
	private_cp_payload_t *this;

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
			.create_attribute_enumerator = _create_attribute_enumerator,
			.add_attribute = _add_attribute,
			.get_type = _get_config_type,
			.destroy = _destroy,
		},
		.next_payload = NO_PAYLOAD,
		.payload_length = CP_PAYLOAD_HEADER_LENGTH,
		.attributes = linked_list_create(),
		.type = type,
	);
	return &this->public;
}

/*
 * Described in header.
 */
cp_payload_t *cp_payload_create()
{
	return cp_payload_create_type(CFG_REQUEST);
}
