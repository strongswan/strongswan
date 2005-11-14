/**
 * @file transform_attribute.c
 * 
 * @brief Declaration of the class transform_attribute_t. 
 * 
 * An object of this type represents an IKEv2 TRANSFORM attribute.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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
 
/* offsetof macro */
#include <stddef.h>

#include "transform_attribute.h"

#include "encodings.h"
#include "../types.h"
#include "../utils/allocator.h"

/**
 * Private data of an transform_attribute_t Object
 * 
 */
typedef struct private_transform_attribute_s private_transform_attribute_t;

struct private_transform_attribute_s {
	/**
	 * public transform_attribute_t interface
	 */
	transform_attribute_t public;
	
	/**
	 * Attribute Format Flag
	 * 
	 * - TRUE means value is stored in attribute_length_or_value
	 * - FALSE means value is stored in attribute_value
	 */
	bool attribute_format;
	
	/**
	 * Type of the attribute
	 */
	u_int16_t attribute_type;
	
	/**
	 * Attribute Length if attribute_format is 0, attribute Value otherwise
	 */
	u_int8_t	 attribute_length_or_value;
	
	/**
	 * Attribute value as chunk if attribute_format is 0 (FALSE)
	 */
	chunk_t attribute_value;
};


/**
 * Encoding rules to parse or generate a Transform attribute
 * 
 * The defined offsets are the positions in a object of type 
 * private_transform_attribute_t.
 * 
 */
encoding_rule_t transform_attribute_encodings[] = {
	/* Flag defining the format of this payload */
	{ ATTRIBUTE_FORMAT,			offsetof(private_transform_attribute_t, attribute_format) 			},
	/* type of the attribute as 15 bit unsigned integer */
	{ ATTRIBUTE_TYPE,			offsetof(private_transform_attribute_t, attribute_type)				},	
	/* Length or value, depending on the attribute format flag */
	{ ATTRIBUTE_LENGTH_OR_VALUE,	offsetof(private_transform_attribute_t, attribute_length_or_value)	},
	/* Value of attribute if attribute format flag is zero */
	{ ATTRIBUTE_VALUE,			offsetof(private_transform_attribute_t, attribute_value) 			}
};

/**
 * Implements payload_t's and transform_attribute_t's destroy function.
 * See #payload_s.destroy or transform_attribute_s.destroy for description.
 */
static status_t destroy(private_transform_attribute_t *this)
{
	if (this->attribute_value.ptr != NULL)
	{
		allocator_free(this->attribute_value.ptr);
	}	
	allocator_free(this);
	
	return SUCCESS;
}

/**
 * Implements payload_t's get_encoding_rules function.
 * See #payload_s.get_encoding_rules for description.
 */
static status_t get_encoding_rules(private_transform_attribute_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = transform_attribute_encodings;
	*rule_count = sizeof(transform_attribute_encodings) / sizeof(encoding_rule_t);
	
	return SUCCESS;
}

/**
 * Implements payload_t's get_type function.
 * See #payload_s.get_type for description.
 */
static payload_type_t get_type(private_transform_attribute_t *this)
{
	return TRANSFORM_ATTRIBUTE;
}

/**
 * Implements payload_t's get_next_type function.
 * See #payload_s.get_next_type for description.
 */
static payload_type_t get_next_type(private_transform_attribute_t *this)
{
	return (NO_PAYLOAD);
}

/**
 * Implements payload_t's get_length function.
 * See #payload_s.get_length for description.
 */
static size_t get_length(private_transform_attribute_t *this)
{
	if (this->attribute_format == TRUE)
	{
		/*Attribute size is only 4 byte */
		return 4;
	}
	return (this->attribute_length_or_value + 4);
}

/*
 * Described in header
 */
transform_attribute_t *transform_attribute_create()
{
	private_transform_attribute_t *this = allocator_alloc_thing(private_transform_attribute_t);
	if (this == NULL)
	{
		return NULL;	
	}	
	
	this->public.payload_interface.get_encoding_rules = (status_t (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (status_t (*) (payload_t *))destroy;
	this->public.destroy = (status_t (*) (transform_attribute_t *)) destroy;
	
	/* set default values of the fields */
	this->attribute_format = TRUE;
	this->attribute_type = 0;
	this->attribute_length_or_value = 0;
	this->attribute_value.ptr = NULL;
	this->attribute_value.len = 0;

	return (&(this->public));
}

