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

#include <string.h>
#include <stddef.h>

#include "transform_attribute.h"

#include <encoding/payloads/encodings.h>
#include <library.h>

typedef struct private_transform_attribute_t private_transform_attribute_t;

/**
 * Private data of an transform_attribute_t object.
 */
struct private_transform_attribute_t {

	/**
	 * Public transform_attribute_t interface.
	 */
	transform_attribute_t public;

	/**
	 * Attribute Format Flag.
	 *
	 * - TRUE means value is stored in attribute_length_or_value
	 * - FALSE means value is stored in attribute_value
	 */
	bool attribute_format;

	/**
	 * Type of the attribute.
	 */
	u_int16_t attribute_type;

	/**
	 * Attribute Length if attribute_format is 0, attribute Value otherwise.
	 */
	u_int16_t attribute_length_or_value;

	/**
	 * Attribute value as chunk if attribute_format is 0 (FALSE).
	 */
	chunk_t attribute_value;
};


ENUM_BEGIN(transform_attribute_type_name, ATTRIBUTE_UNDEFINED, ATTRIBUTE_UNDEFINED,
	"ATTRIBUTE_UNDEFINED");
ENUM_NEXT(transform_attribute_type_name, KEY_LENGTH, KEY_LENGTH, ATTRIBUTE_UNDEFINED,
	"KEY_LENGTH");
ENUM_END(transform_attribute_type_name, KEY_LENGTH);

/**
 * Encoding rules to parse or generate a Transform attribute.
 *
 * The defined offsets are the positions in a object of type
 * private_transform_attribute_t.
 */
encoding_rule_t transform_attribute_encodings[] = {
	/* Flag defining the format of this payload */
	{ ATTRIBUTE_FORMAT,			offsetof(private_transform_attribute_t, attribute_format) 			},
	/* type of the attribute as 15 bit unsigned integer */
	{ ATTRIBUTE_TYPE,			offsetof(private_transform_attribute_t, attribute_type)				},
	/* Length or value, depending on the attribute format flag */
	{ ATTRIBUTE_LENGTH_OR_VALUE,offsetof(private_transform_attribute_t, attribute_length_or_value)	},
	/* Value of attribute if attribute format flag is zero */
	{ ATTRIBUTE_VALUE,			offsetof(private_transform_attribute_t, attribute_value) 			}
};

/*
                          1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !A!       Attribute Type        !    AF=0  Attribute Length     !
      !F!                             !    AF=1  Attribute Value      !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                   AF=0  Attribute Value                       !
      !                   AF=1  Not Transmitted                       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

METHOD(payload_t, verify, status_t,
	private_transform_attribute_t *this)
{
	return SUCCESS;
}

METHOD(payload_t, get_encoding_rules, void,
	private_transform_attribute_t *this, encoding_rule_t **rules,
	size_t *rule_count)
{
	*rules = transform_attribute_encodings;
	*rule_count = countof(transform_attribute_encodings);
}

METHOD(payload_t, get_type, payload_type_t,
	private_transform_attribute_t *this)
{
	return TRANSFORM_ATTRIBUTE;
}

METHOD(payload_t, get_next_type, payload_type_t,
	private_transform_attribute_t *this)
{
	return NO_PAYLOAD;
}

METHOD(payload_t, set_next_type, void,
	private_transform_attribute_t *this, payload_type_t type)
{
}

METHOD(payload_t, get_length, size_t,
	private_transform_attribute_t *this)
{
	if (this->attribute_format)
	{
		return 4;
	}
	return this->attribute_length_or_value + 4;
}

METHOD(transform_attribute_t, set_value_chunk, void,
	private_transform_attribute_t *this, chunk_t value)
{
	chunk_free(&this->attribute_value);

	if (value.len != 2)
	{
		this->attribute_value = chunk_clone(value);
		this->attribute_length_or_value = value.len;
		this->attribute_format = FALSE;
	}
	else
	{
		memcpy(&this->attribute_length_or_value, value.ptr, value.len);
	}
}

METHOD(transform_attribute_t, set_value, void,
	private_transform_attribute_t *this, u_int16_t value)
{
	chunk_free(&this->attribute_value);
	this->attribute_length_or_value = value;
	this->attribute_format = TRUE;
}

METHOD(transform_attribute_t, get_value_chunk, chunk_t,
	private_transform_attribute_t *this)
{
	if (this->attribute_format)
	{
		return chunk_from_thing(this->attribute_length_or_value);
	}
	return this->attribute_value;
}

METHOD(transform_attribute_t, get_value, u_int16_t,
	private_transform_attribute_t *this)
{
	return this->attribute_length_or_value;
}

METHOD(transform_attribute_t, set_attribute_type, void,
	private_transform_attribute_t *this, u_int16_t type)
{
	this->attribute_type = type & 0x7FFF;
}

METHOD(transform_attribute_t, get_attribute_type, u_int16_t,
	private_transform_attribute_t *this)
{
	return this->attribute_type;
}

METHOD(transform_attribute_t, clone_, transform_attribute_t*,
	private_transform_attribute_t *this)
{
	private_transform_attribute_t *new_clone;

	new_clone = (private_transform_attribute_t *)transform_attribute_create();

	new_clone->attribute_format = this->attribute_format;
	new_clone->attribute_type = this->attribute_type;
	new_clone->attribute_length_or_value = this->attribute_length_or_value;

	if (!new_clone->attribute_format)
	{
		new_clone->attribute_value = chunk_clone(this->attribute_value);
	}
	return &new_clone->public;
}

METHOD2(payload_t, transform_attribute_t, destroy, void,
	private_transform_attribute_t *this)
{
	free(this->attribute_value.ptr);
	free(this);
}

/*
 * Described in header.
 */
transform_attribute_t *transform_attribute_create()
{
	private_transform_attribute_t *this;

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
			.set_value_chunk = _set_value_chunk,
			.set_value = _set_value,
			.get_value_chunk = _get_value_chunk,
			.get_value = _get_value,
			.set_attribute_type = _set_attribute_type,
			.get_attribute_type = _get_attribute_type,
			.clone = _clone_,
			.destroy = _destroy,
		},
		.attribute_format = TRUE,
	);
	return &this->public;
}

/*
 * Described in header.
 */
transform_attribute_t *transform_attribute_create_key_length(u_int16_t key_length)
{
	transform_attribute_t *attribute = transform_attribute_create();
	attribute->set_attribute_type(attribute, KEY_LENGTH);
	attribute->set_value(attribute, key_length);
	return attribute;
}
