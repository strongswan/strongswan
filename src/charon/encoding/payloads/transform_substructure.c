/**
 * @file transform_substructure.h
 * 
 * @brief Implementation of transform_substructure_t.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
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
#include <types.h>
#include <utils/linked_list.h>
#include <utils/logger_manager.h>


typedef struct private_transform_substructure_t private_transform_substructure_t;

/**
 * Private data of an transform_substructure_t object.
 * 
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
	
 	/**
	 * assigned logger
	 */
	logger_t *logger;
	
	/**
	 * @brief Computes the length of this substructure.
	 *
	 * @param this 	calling private_transform_substructure_t object
	 */
	void (*compute_length) (private_transform_substructure_t *this);
};


/**
 * Encoding rules to parse or generate a Transform substructure.
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


/**
 * Implementation of payload_t.verify.
 */
static status_t verify(private_transform_substructure_t *this)
{
	status_t status = SUCCESS;
	iterator_t *iterator;
	
	if ((this->next_payload != NO_PAYLOAD) && (this->next_payload != 3))
	{
		/* must be 0 or 3 */
		this->logger->log(this->logger, ERROR, "inconsistent next payload");
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
			this->logger->log(this->logger, ERROR, "invalid transform type: %d",
							  this->transform_type);
			return FAILED;
		}
	}
	iterator = this->attributes->create_iterator(this->attributes,TRUE);
	
	while(iterator->has_next(iterator))
	{
		payload_t *current_attributes;
		iterator->current(iterator,(void **)&current_attributes);

		status = current_attributes->verify(current_attributes);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, ERROR, 
							  "TRANSFORM_ATTRIBUTE verification failed");
		}
	}
	iterator->destroy(iterator);
	
	/* proposal number is checked in SA payload */	
	return status;
}

/**
 * Implementation of payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_transform_substructure_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = transform_substructure_encodings;
	*rule_count = sizeof(transform_substructure_encodings) / sizeof(encoding_rule_t);
}

/**
 * Implementation of payload_t.get_type.
 */
static payload_type_t get_type(private_transform_substructure_t *this)
{
	return TRANSFORM_SUBSTRUCTURE;
}

/**
 * Implementation of payload_t.get_next_type.
 */
static payload_type_t get_next_type(private_transform_substructure_t *this)
{
	return (this->next_payload);
}

/**
 * Implementation of payload_t.get_length.
 */
static size_t get_length(private_transform_substructure_t *this)
{
	this->compute_length(this);
		
	return this->transform_length;
}

/**
 * Implementation of transform_substructure_t.create_transform_attribute_iterator.
 */
static iterator_t *create_transform_attribute_iterator (private_transform_substructure_t *this,bool forward)
{
	return this->attributes->create_iterator(this->attributes,forward);
}

/**
 * Implementation of transform_substructure_t.add_transform_attribute.
 */
static void add_transform_attribute (private_transform_substructure_t *this,transform_attribute_t *attribute)
{
	this->attributes->insert_last(this->attributes,(void *) attribute);
	this->compute_length(this);
}

/**
 * Implementation of transform_substructure_t.set_is_last_transform.
 */
static void set_is_last_transform (private_transform_substructure_t *this, bool is_last)
{
	this->next_payload = (is_last) ? 0: TRANSFORM_TYPE_VALUE;
}

/**
 * Implementation of transform_substructure_t.get_is_last_transform.
 */
static bool get_is_last_transform (private_transform_substructure_t *this)
{
	return ((this->next_payload == TRANSFORM_TYPE_VALUE) ? FALSE : TRUE);
}

/**
 * Implementation of payload_t.set_next_type.
 */
static void set_next_type(private_transform_substructure_t *this,payload_type_t type)
{
}

/**
 * Implementation of transform_substructure_t.set_transform_type.
 */
static void set_transform_type (private_transform_substructure_t *this,u_int8_t type)
{
	this->transform_type = type;
}
	
/**
 * Implementation of transform_substructure_t.get_transform_type.
 */
static u_int8_t get_transform_type (private_transform_substructure_t *this)
{
	return this->transform_type;
}

/**
 * Implementation of transform_substructure_t.set_transform_id.
 */
static void set_transform_id (private_transform_substructure_t *this,u_int16_t id)
{
	this->transform_id = id;
}
	
/**
 * Implementation of transform_substructure_t.get_transform_id.
 */
static u_int16_t get_transform_id (private_transform_substructure_t *this)
{
	return this->transform_id;
}

/**
 * Implementation of private_transform_substructure_t.compute_length.
 */
static void compute_length (private_transform_substructure_t *this)
{
	iterator_t *iterator;
	size_t length = TRANSFORM_SUBSTRUCTURE_HEADER_LENGTH;
	iterator = this->attributes->create_iterator(this->attributes,TRUE);
	while (iterator->has_next(iterator))
	{
		payload_t * current_attribute;
		iterator->current(iterator,(void **) &current_attribute);
		length += current_attribute->get_length(current_attribute);
	}
	iterator->destroy(iterator);
	
	this->transform_length = length;
}

/**
 * Implementation of transform_substructure_t.clone.
 */
static transform_substructure_t *clone_(private_transform_substructure_t *this)
{
	private_transform_substructure_t *new_clone;
	iterator_t *attributes;
	
	new_clone = (private_transform_substructure_t *) transform_substructure_create();
	
	new_clone->next_payload = this->next_payload;
	new_clone->transform_type = this->transform_type;
	new_clone->transform_id = this->transform_id;

	attributes = this->attributes->create_iterator(this->attributes,FALSE);

	while (attributes->has_next(attributes))
	{
		transform_attribute_t *current_attribute;
		transform_attribute_t *current_attribute_clone;
		attributes->current(attributes,(void **) &current_attribute);

		current_attribute_clone = current_attribute->clone(current_attribute);
		
		new_clone->public.add_transform_attribute(&(new_clone->public),current_attribute_clone);
	}
	
	attributes->destroy(attributes);	
	
	return &(new_clone->public);
}


/**
 * Implementation of transform_substructure_t.get_key_length.
 */
static status_t get_key_length(private_transform_substructure_t *this, u_int16_t *key_length)
{
	iterator_t *attributes;
	
	attributes = this->attributes->create_iterator(this->attributes,TRUE);

	while (attributes->has_next(attributes))
	{
		transform_attribute_t *current_attribute;
		attributes->current(attributes,(void **) &current_attribute);

		if (current_attribute->get_attribute_type(current_attribute) == KEY_LENGTH)
		{
			*key_length = current_attribute->get_value(current_attribute);
			attributes->destroy(attributes);	
			return SUCCESS;
		}
		
	}
	attributes->destroy(attributes);
	
	return FAILED;
}


/**
 * Implementation of transform_substructure_t.destroy and payload_t.destroy.
 */
static void destroy(private_transform_substructure_t *this)
{
	/* all proposals are getting destroyed */ 
	while (this->attributes->get_count(this->attributes) > 0)
	{
		transform_attribute_t *current_attribute;
		this->attributes->remove_last(this->attributes,(void **)&current_attribute);
		current_attribute->destroy(current_attribute);
	}
	this->attributes->destroy(this->attributes);
	
	free(this);
}

/*
 * Described in header.
 */
transform_substructure_t *transform_substructure_create()
{
	private_transform_substructure_t *this = malloc_thing(private_transform_substructure_t);

	/* payload interface */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t *,payload_type_t)) set_next_type;	
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (void (*) (payload_t *))destroy;
	
	/* public functions */
	this->public.create_transform_attribute_iterator = (iterator_t * (*) (transform_substructure_t *,bool)) create_transform_attribute_iterator;
	this->public.add_transform_attribute = (void (*) (transform_substructure_t *,transform_attribute_t *)) add_transform_attribute;
	this->public.set_is_last_transform = (void (*) (transform_substructure_t *,bool)) set_is_last_transform;
	this->public.get_is_last_transform = (bool (*) (transform_substructure_t *)) get_is_last_transform;
	this->public.set_transform_type = (void (*) (transform_substructure_t *,u_int8_t)) set_transform_type;
	this->public.get_transform_type = (u_int8_t (*) (transform_substructure_t *)) get_transform_type;
	this->public.set_transform_id = (void (*) (transform_substructure_t *,u_int16_t)) set_transform_id;
	this->public.get_transform_id = (u_int16_t (*) (transform_substructure_t *)) get_transform_id;
	this->public.get_key_length = (status_t (*) (transform_substructure_t *,u_int16_t *)) get_key_length;
	this->public.clone = (transform_substructure_t* (*) (transform_substructure_t *)) clone_;
	this->public.destroy = (void (*) (transform_substructure_t *)) destroy;
	
	/* private functions */
	this->compute_length = compute_length;
	
	/* set default values of the fields */
	this->next_payload = NO_PAYLOAD;
	this->transform_length = TRANSFORM_SUBSTRUCTURE_HEADER_LENGTH;
	this->transform_id = 0;
	this->transform_type = 0;
	this->attributes = linked_list_create();
	this->logger = logger_manager->get_logger(logger_manager, PAYLOAD);
	
	return (&(this->public));
}

/*
 * Described in header
 */
transform_substructure_t *transform_substructure_create_type(transform_type_t transform_type, u_int16_t transform_id, u_int16_t key_length)
{
	transform_substructure_t *transform = transform_substructure_create();
	
	transform->set_transform_type(transform,transform_type);
	transform->set_transform_id(transform,transform_id);
	
	/* a keylength attribute is only created for variable length algos */
	if (transform_type == ENCRYPTION_ALGORITHM &&
		(transform_id == ENCR_AES_CBC ||
		 transform_id == ENCR_IDEA ||
		 transform_id == ENCR_CAST ||
		 transform_id == ENCR_BLOWFISH))
	{
		transform_attribute_t *attribute = transform_attribute_create_key_length(key_length);
		transform->add_transform_attribute(transform,attribute);
	}

	return transform;
}
