/**
 * @file transform_substructure.h
 * 
 * @brief Declaration of the class transform_substructure_t. 
 * 
 * An object of this type represents an IKEv2 TRANSFORM Substructure and contains Attributes.
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

#include "transform_substructure.h"

#include "transform_attribute.h"
#include "encodings.h"
#include "../types.h"
#include "../utils/allocator.h"
#include "../utils/linked_list.h"

/**
 * Private data of an transform_substructure_t' Object
 * 
 */
typedef struct private_transform_substructure_s private_transform_substructure_t;

struct private_transform_substructure_s {
	/**
	 * public transform_substructure_t interface
	 */
	transform_substructure_t public;
	
	/**
	 * next payload type
	 */
	u_int8_t  next_payload;

	
	/**
	 * Length of this payload
	 */
	u_int16_t transform_length;
	
	
	/**
	 * Type of the transform
	 */
	u_int8_t	 transform_type;
	
	/**
	 * Transform ID
	 */
	u_int16_t transform_id;
	
 	/**
 	 * Transforms Attributes are stored in a linked_list_t
 	 */
	linked_list_t *attributes;
	
	/**
	 * @brief Computes the length of this substructure.
	 *
	 * @param this 	calling private_transform_substructure_t object
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*compute_length) (private_transform_substructure_t *this);
};


/**
 * Encoding rules to parse or generate a Transform substructure
 * 
 * The defined offsets are the positions in a object of type 
 * private_transform_substructure_t.
 * 
 */
encoding_rule_t transform_substructure_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_transform_substructure_t, next_payload) 		},
	/* Reserved Byte is skipped */
	{ RESERVED_BYTE,		0																},	
	/* Length of the whole transform substructure*/
	{ PAYLOAD_LENGTH,		offsetof(private_transform_substructure_t, transform_length)	},	
	/* transform type is a number of 8 bit */
	{ U_INT_8,				offsetof(private_transform_substructure_t, transform_type) 	},	
	/* Reserved Byte is skipped */
	{ RESERVED_BYTE,		0																},	
	/* tranform ID is a number of 8 bit */
	{ U_INT_16,				offsetof(private_transform_substructure_t, transform_id)		},	
	/* Attributes are stored in a transform attribute, 
	   offset points to a linked_list_t pointer */
	{ TRANSFORM_ATTRIBUTES,	offsetof(private_transform_substructure_t, attributes) 		}
};

/**
 * Implements payload_t's and transform_substructure_t's destroy function.
 * See #payload_s.destroy or transform_substructure_s.destroy for description.
 */
static status_t destroy(private_transform_substructure_t *this)
{
	/* all proposals are getting destroyed */ 
	while (this->attributes->get_count(this->attributes) > 0)
	{
		transform_attribute_t *current_attribute;
		if (this->attributes->remove_last(this->attributes,(void **)&current_attribute) != SUCCESS)
		{
			break;
		}
		current_attribute->destroy(current_attribute);
	}
	this->attributes->destroy(this->attributes);
	
	allocator_free(this);
	
	return SUCCESS;
}

/**
 * Implements payload_t's get_encoding_rules function.
 * See #payload_s.get_encoding_rules for description.
 */
static status_t get_encoding_rules(private_transform_substructure_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = transform_substructure_encodings;
	*rule_count = sizeof(transform_substructure_encodings) / sizeof(encoding_rule_t);
	
	return SUCCESS;
}

/**
 * Implements payload_t's get_type function.
 * See #payload_s.get_type for description.
 */
static payload_type_t get_type(private_transform_substructure_t *this)
{
	return TRANSFORM_SUBSTRUCTURE;
}

/**
 * Implements payload_t's get_next_type function.
 * See #payload_s.get_next_type for description.
 */
static payload_type_t get_next_type(private_transform_substructure_t *this)
{
	return (this->next_payload);
}

/**
 * Implements payload_t's get_length function.
 * See #payload_s.get_length for description.
 */
static size_t get_length(private_transform_substructure_t *this)
{
	this->compute_length(this);
		
	return this->transform_length;
}

/**
 * Implements transform_substructure_t's create_transform_attribute_iterator function.
 * See #transform_substructure_s.create_transform_attribute_iterator for description.
 */
static status_t create_transform_attribute_iterator (private_transform_substructure_t *this,linked_list_iterator_t **iterator,bool forward)
{
	return (this->attributes->create_iterator(this->attributes,iterator,forward));
}

/**
 * Implements transform_substructure_t's add_transform_attribute function.
 * See #transform_substructure_s.add_transform_attribute for description.
 */
static status_t add_transform_attribute (private_transform_substructure_t *this,transform_attribute_t *attribute)
{
	status_t status;
	status = this->attributes->insert_last(this->attributes,(void *) attribute);
	this->compute_length(this);
	return status;
}

/**
 * Implements transform_substructure_t's set_is_last_transform function.
 * See #transform_substructure_s.set_is_last_transform for description.
 */
static status_t set_is_last_transform (private_transform_substructure_t *this, bool is_last)
{
	this->next_payload = (is_last) ? 0: TRANSFORM_TYPE_VALUE;
	return SUCCESS;
}

/**
 * Implements transform_substructure_t's get_is_last_transform function.
 * See #transform_substructure_s.get_is_last_transform for description.
 */
static bool get_is_last_transform (private_transform_substructure_t *this)
{
	return ((this->next_payload == TRANSFORM_TYPE_VALUE) ? FALSE : TRUE);
}

/**
 * Implements transform_substructure_t's set_transform_type function.
 * See #transform_substructure_s.set_transform_type for description.
 */
static status_t set_transform_type (private_transform_substructure_t *this,u_int8_t type)
{
	this->transform_type = type;
	return SUCCESS;
}
	
/**
 * Implements transform_substructure_t's get_transform_type function.
 * See #transform_substructure_s.get_transform_type for description.
 */
static u_int8_t get_transform_type (private_transform_substructure_t *this)
{
	return this->transform_type;
}

/**
 * Implements transform_substructure_t's set_transform_id function.
 * See #transform_substructure_s.set_transform_id for description.
 */
static status_t set_transform_id (private_transform_substructure_t *this,u_int16_t id)
{
	this->transform_id = id;
	return SUCCESS;
}
	
/**
 * Implements transform_substructure_t's get_transform_id function.
 * See #transform_substructure_s.get_transform_id for description.
 */
static u_int16_t get_transform_id (private_transform_substructure_t *this)
{
	return this->transform_id;
}

/**
 * Implements private_transform_substructure_t's compute_length function.
 * See #private_transform_substructure_s.compute_length for description.
 */
static status_t compute_length (private_transform_substructure_t *this)
{
	linked_list_iterator_t *iterator;
	status_t status;
	size_t length = TRANSFORM_SUBSTRUCTURE_HEADER_LENGTH;
	status = this->attributes->create_iterator(this->attributes,&iterator,TRUE);
	if (status != SUCCESS)
	{
		return length;
	}
	while (iterator->has_next(iterator))
	{
		payload_t * current_attribute;
		iterator->current(iterator,(void **) &current_attribute);
		length += current_attribute->get_length(current_attribute);
	}
	iterator->destroy(iterator);
		
	return SUCCESS;
}

/*
 * Described in header
 */
transform_substructure_t *transform_substructure_create()
{
	private_transform_substructure_t *this = allocator_alloc_thing(private_transform_substructure_t);
	if (this == NULL)
	{
		return NULL;	
	}	
	
	this->public.payload_interface.get_encoding_rules = (status_t (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (status_t (*) (payload_t *))destroy;
	this->public.create_transform_attribute_iterator = (status_t (*) (transform_substructure_t *,linked_list_iterator_t **,bool)) create_transform_attribute_iterator;
	this->public.add_transform_attribute = (status_t (*) (transform_substructure_t *,transform_attribute_t *)) add_transform_attribute;
	this->public.set_is_last_transform = (status_t (*) (transform_substructure_t *,bool)) set_is_last_transform;
	this->public.get_is_last_transform = (bool (*) (transform_substructure_t *)) get_is_last_transform;
	this->public.set_transform_type = (status_t (*) (transform_substructure_t *,u_int8_t)) set_transform_type;
	this->public.get_transform_type = (u_int8_t (*) (transform_substructure_t *)) get_transform_type;
	this->public.set_transform_id = (status_t (*) (transform_substructure_t *,u_int16_t)) set_transform_id;
	this->public.get_transform_id = (u_int16_t (*) (transform_substructure_t *)) get_transform_id;
	this->public.destroy = (status_t (*) (transform_substructure_t *)) destroy;
	
	/* private functions */
	this->compute_length = compute_length;
	
	/* set default values of the fields */
	this->next_payload = NO_PAYLOAD;
	this->transform_length = TRANSFORM_SUBSTRUCTURE_HEADER_LENGTH;
	this->transform_id = 0;
	this->transform_type = 0;

	this->attributes = linked_list_create();
	
	if (this->attributes == NULL)
	{
		allocator_free(this);
		return NULL;
	}
	return (&(this->public));
}
