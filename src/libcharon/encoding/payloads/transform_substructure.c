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

#include "transform_substructure.h"

#include <encoding/payloads/transform_attribute.h>
#include <encoding/payloads/encodings.h>
#include <library.h>
#include <utils/linked_list.h>
#include <daemon.h>

typedef struct private_transform_substructure_t private_transform_substructure_t;

/**
 * Private data of an transform_substructure_t object.
 */
struct private_transform_substructure_t {

	/**
	 * Public transform_substructure_t interface.
	 */
	transform_substructure_t public;

	/**
	 * Next payload type.
	 */
	u_int8_t  next_payload;
	/**
	 * Reserved bytes
	 */
	u_int8_t reserved[2];

	/**
	 * Length of this payload.
	 */
	u_int16_t transform_length;

	/**
	 * Type of the transform.
	 */
	u_int8_t transform_type;

	/**
	 * Transform ID.
	 */
	u_int16_t transform_id;

	/**
	 * Transforms Attributes are stored in a linked_list_t.
	 */
	linked_list_t *attributes;
};

/**
 * Encoding rules to parse or generate a Transform substructure.
 *
 * The defined offsets are the positions in a object of type
 * private_transform_substructure_t.
 */
encoding_rule_t transform_substructure_encodings[] = {
	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,				offsetof(private_transform_substructure_t, next_payload)	},
	/* 1 Reserved Byte */
	{ RESERVED_BYTE,		offsetof(private_transform_substructure_t, reserved[0])		},
	/* Length of the whole transform substructure*/
	{ PAYLOAD_LENGTH,		offsetof(private_transform_substructure_t, transform_length)},
	/* transform type is a number of 8 bit */
	{ U_INT_8,				offsetof(private_transform_substructure_t, transform_type)	},
	/* 1 Reserved Byte */
	{ RESERVED_BYTE,		offsetof(private_transform_substructure_t, reserved[1])		},
	/* transform ID is a number of 8 bit */
	{ U_INT_16,				offsetof(private_transform_substructure_t, transform_id)	},
	/* Attributes are stored in a transform attribute,
	   offset points to a linked_list_t pointer */
	{ TRANSFORM_ATTRIBUTES,	offsetof(private_transform_substructure_t, attributes)		}
};

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! 0 (last) or 3 !   RESERVED    !        Transform Length       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !Transform Type !   RESERVED    !          Transform ID         !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                      Transform Attributes                     ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

METHOD(payload_t, verify, status_t,
	private_transform_substructure_t *this)
{
	status_t status = SUCCESS;
	enumerator_t *enumerator;
	payload_t *attribute;

	if (this->next_payload != NO_PAYLOAD && this->next_payload != 3)
	{
		DBG1(DBG_ENC, "inconsistent next payload");
		return FAILED;
	}

	switch (this->transform_type)
	{
		case ENCRYPTION_ALGORITHM:
		case PSEUDO_RANDOM_FUNCTION:
		case INTEGRITY_ALGORITHM:
		case DIFFIE_HELLMAN_GROUP:
		case EXTENDED_SEQUENCE_NUMBERS:
			/* we don't check transform ID, we want to reply
			 * cleanly with NO_PROPOSAL_CHOSEN or so if we don't support it */
			break;
		default:
		{
			DBG1(DBG_ENC, "invalid transform type: %d", this->transform_type);
			return FAILED;
		}
	}

	enumerator = this->attributes->create_enumerator(this->attributes);
	while (enumerator->enumerate(enumerator, &attribute))
	{
		status = attribute->verify(attribute);
		if (status != SUCCESS)
		{
			DBG1(DBG_ENC, "TRANSFORM_ATTRIBUTE verification failed");
			break;
		}
	}
	enumerator->destroy(enumerator);

	/* proposal number is checked in SA payload */
	return status;
}

METHOD(payload_t, get_encoding_rules, void,
	private_transform_substructure_t *this, encoding_rule_t **rules,
	size_t *rule_count)
{
	*rules = transform_substructure_encodings;
	*rule_count = countof(transform_substructure_encodings);
}

METHOD(payload_t, get_type, payload_type_t,
	private_transform_substructure_t *this)
{
	return TRANSFORM_SUBSTRUCTURE;
}

METHOD(payload_t, get_next_type, payload_type_t,
	private_transform_substructure_t *this)
{
	return this->next_payload;
}

/**
 * recompute the length of the payload.
 */
static void compute_length (private_transform_substructure_t *this)
{
	enumerator_t *enumerator;
	payload_t *attribute;

	this->transform_length = TRANSFORM_SUBSTRUCTURE_HEADER_LENGTH;
	enumerator = this->attributes->create_enumerator(this->attributes);
	while (enumerator->enumerate(enumerator, &attribute))
	{
		this->transform_length += attribute->get_length(attribute);
	}
	enumerator->destroy(enumerator);
}

METHOD(payload_t, get_length, size_t,
	private_transform_substructure_t *this)
{
	return this->transform_length;
}

METHOD(transform_substructure_t, set_is_last_transform, void,
	private_transform_substructure_t *this, bool is_last)
{
	this->next_payload = is_last ? 0: TRANSFORM_TYPE_VALUE;
}

METHOD(payload_t, set_next_type, void,
	private_transform_substructure_t *this,payload_type_t type)
{
}

METHOD(transform_substructure_t, get_transform_type, u_int8_t,
	private_transform_substructure_t *this)
{
	return this->transform_type;
}

METHOD(transform_substructure_t, get_transform_id, u_int16_t,
	private_transform_substructure_t *this)
{
	return this->transform_id;
}

METHOD(transform_substructure_t, get_key_length, status_t,
	private_transform_substructure_t *this, u_int16_t *key_length)
{
	enumerator_t *enumerator;
	transform_attribute_t *attribute;

	enumerator = this->attributes->create_enumerator(this->attributes);
	while (enumerator->enumerate(enumerator, &attribute))
	{
		if (attribute->get_attribute_type(attribute) == KEY_LENGTH)
		{
			*key_length = attribute->get_value(attribute);
			enumerator->destroy(enumerator);
			return SUCCESS;
		}
	}
	enumerator->destroy(enumerator);
	return FAILED;
}

METHOD2(payload_t, transform_substructure_t, destroy, void,
	private_transform_substructure_t *this)
{
	this->attributes->destroy_offset(this->attributes,
									 offsetof(transform_attribute_t, destroy));
	free(this);
}

/*
 * Described in header.
 */
transform_substructure_t *transform_substructure_create()
{
	private_transform_substructure_t *this;

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
			.set_is_last_transform = _set_is_last_transform,
			.get_transform_type = _get_transform_type,
			.get_transform_id = _get_transform_id,
			.get_key_length = _get_key_length,
			.destroy = _destroy,
		},
		.next_payload = NO_PAYLOAD,
		.transform_length = TRANSFORM_SUBSTRUCTURE_HEADER_LENGTH,
		.attributes = linked_list_create(),
	);
	return &this->public;
}

/*
 * Described in header
 */
transform_substructure_t *transform_substructure_create_type(
					transform_type_t type, u_int16_t id, u_int16_t key_length)
{
	private_transform_substructure_t *this;

	this = (private_transform_substructure_t*)transform_substructure_create();

	this->transform_type = type;
	this->transform_id = id;
	if (key_length)
	{
		this->attributes->insert_last(this->attributes,
					(void*)transform_attribute_create_key_length(key_length));
		compute_length(this);
	}
	return &this->public;
}

