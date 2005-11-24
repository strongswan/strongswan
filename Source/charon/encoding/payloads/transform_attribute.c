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

#include <encoding/payloads/encodings.h>
#include <types.h>
#include <utils/allocator.h>

typedef struct private_transform_attribute_t private_transform_attribute_t;

/**
 * Private data of an transform_attribute_t Object
 * 
 */
struct private_transform_attribute_t {
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
	u_int16_t attribute_length_or_value;
	
	/**
	 * Attribute value as chunk if attribute_format is 0 (FALSE)
	 */
	chunk_t attribute_value;
};



/** 
 * string mappings for transform_attribute_type_t
 */
mapping_t transform_attribute_type_m[] = {
	{ATTRIBUTE_UNDEFINED, "ATTRIBUTE_UNDEFINED"},
	{KEY_LENGTH, "KEY_LENGTH"},
	{MAPPING_END, NULL}
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

/**
 * Implements payload_t's verify function.
 * See #payload_s.verify for description.
 */
static status_t verify(private_transform_attribute_t *this)
{
	if (this->attribute_type != KEY_LENGTH)
	{
		return FAILED;
	}
	
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
 * Implements payload_t's set_next_type function.
 * See #payload_s.set_next_type for description.
 */
static status_t set_next_type(private_transform_attribute_t *this,payload_type_t type)
{
	return SUCCESS;
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
/**
 * Implements transform_attribute_t's set_value function.
 * See #transform_attribute_s.set_value for description.
 */
static status_t set_value_chunk(private_transform_attribute_t *this, chunk_t value)
{
	if (this->attribute_value.ptr != NULL)
	{
		/* free existing value */
		allocator_free(this->attribute_value.ptr);
		this->attribute_value.ptr = NULL;
		this->attribute_value.len = 0;
		
	}
	
	if (value.len > 2)
	{
		this->attribute_value.ptr = allocator_clone_bytes(value.ptr,value.len);
		if (this->attribute_value.ptr == NULL)
		{
			return OUT_OF_RES;
		}
		this->attribute_value.len = value.len;
		this->attribute_length_or_value = value.len;
		/* attribute has not a fixed length */
		this->attribute_format = FALSE;		
	}
	else
	{
		memcpy(&(this->attribute_length_or_value),value.ptr,value.len);
	}
	return SUCCESS;
}

/**
 * Implements transform_attribute_t's set_value function.
 * See #transform_attribute_s.set_value for description.
 */
static status_t set_value(private_transform_attribute_t *this, u_int16_t value)
{
	if (this->attribute_value.ptr != NULL)
	{
		/* free existing value */
		allocator_free(this->attribute_value.ptr);
		this->attribute_value.ptr = NULL;
		this->attribute_value.len = 0;
		
	}
	this->attribute_length_or_value = value;
	return SUCCESS;
}

/**
 * Implements transform_attribute_t's get_value_chunk function.
 * See #transform_attribute_s.get_value_chunk for description.
 */
static chunk_t get_value_chunk (private_transform_attribute_t *this)
{
	chunk_t value;

	if (this->attribute_format == FALSE)
	{
		value.ptr = this->attribute_value.ptr;
		value.len = this->attribute_value.len;		
	}
	else
	{
		value.ptr = (void *) &(this->attribute_length_or_value);
		value.len = 2;
	}
	
	return value;
}

/**
 * Implements transform_attribute_t's get_value function.
 * See #transform_attribute_s.get_value for description.
 */
static u_int16_t get_value (private_transform_attribute_t *this)
{
	return this->attribute_length_or_value;
}


/**
 * Implements transform_attribute_t's set_attribute_type function.
 * See #transform_attribute_s.set_attribute_type for description.
 */
static status_t set_attribute_type (private_transform_attribute_t *this, u_int16_t type)
{
	this->attribute_type = type & 0x7FFF;
	return SUCCESS;
}

/**
 * Implements transform_attribute_t's get_attribute_type function.
 * See #transform_attribute_s.get_attribute_type for description.
 */
static u_int16_t get_attribute_type (private_transform_attribute_t *this)
{
	return this->attribute_type;
}

/**
 * Implements transform_attribute_t's clone function.
 * See transform_attribute_s.clone for description.
 */
static status_t clone(private_transform_attribute_t *this,transform_attribute_t **clone)
{
	private_transform_attribute_t *new_clone;
	
	new_clone = (private_transform_attribute_t *) transform_attribute_create();
	
	new_clone->attribute_format = this->attribute_format;
	new_clone->attribute_type = this->attribute_type;
	new_clone->attribute_length_or_value = this->attribute_length_or_value;
	
	if (!new_clone->attribute_format)
	{
		new_clone->attribute_value.ptr = allocator_clone_bytes(this->attribute_value.ptr,this->attribute_value.len);		
		new_clone->attribute_value.len = this->attribute_value.len;
		if (new_clone->attribute_value.ptr == NULL)
		{
			new_clone->public.destroy(&(new_clone->public));
			return OUT_OF_RES;
		}
	}
	
	*clone = (transform_attribute_t *) new_clone;
	return SUCCESS;
}

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
	
	/* payload interface */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (status_t (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (status_t (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (status_t (*) (payload_t *))destroy;
	
	/* public functions */
	this->public.set_value_chunk = (status_t (*) (transform_attribute_t *,chunk_t)) set_value_chunk;
	this->public.set_value = (status_t (*) (transform_attribute_t *,u_int16_t)) set_value;
	this->public.get_value_chunk = (chunk_t (*) (transform_attribute_t *)) get_value_chunk;
	this->public.get_value = (u_int16_t (*) (transform_attribute_t *)) get_value;
	this->public.set_attribute_type = (status_t (*) (transform_attribute_t *,u_int16_t type)) set_attribute_type;
	this->public.get_attribute_type = (u_int16_t (*) (transform_attribute_t *)) get_attribute_type;
	this->public.clone = (status_t (*) (transform_attribute_t *,transform_attribute_t **)) clone;
	this->public.destroy = (status_t (*) (transform_attribute_t *)) destroy;
	
	/* set default values of the fields */
	this->attribute_format = TRUE;
	this->attribute_type = 0;
	this->attribute_length_or_value = 0;
	this->attribute_value.ptr = NULL;
	this->attribute_value.len = 0;

	return (&(this->public));
}

