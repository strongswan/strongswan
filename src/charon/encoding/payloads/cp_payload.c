/**
 * @file cp_payload.c
 * 
 * @brief Implementation of cp_payload_t.
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

#include "cp_payload.h"

#include <encoding/payloads/encodings.h>
#include <utils/linked_list.h>


/** 
 * String mappings for config_type_t.
 */
mapping_t config_type_m[] = {
	{CFG_REQUEST, "CFG_REQUEST"},
	{CFG_REPLY, "CFG_REPLY"},
	{CFG_SET, "CFG_SET"},
	{CFG_ACK, "CFG_ACK"},
	{MAPPING_END, NULL}
};


typedef struct private_cp_payload_t private_cp_payload_t;

/**
 * Private data of an cp_payload_t object.
 * 
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
	 * Length of this payload.
	 */
	u_int16_t payload_length;
	
	/**
	 * Configuration Attributes in this payload are stored in a linked_list_t.
	 */
	linked_list_t * attributes;
	
	/**
	 * Config Type.
	 */
	u_int8_t config_type;
	
	/**
	 * @brief Computes the length of this payload.
	 *
	 * @param this 	calling private_cp_payload_t object
	 */
	void (*compute_length) (private_cp_payload_t *this);
};

/**
 * Encoding rules to parse or generate a IKEv2-CP Payload
 * 
 * The defined offsets are the positions in a object of type 
 * private_cp_payload_t.
 * 
 */
encoding_rule_t cp_payload_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,		offsetof(private_cp_payload_t, next_payload) 			},
	/* the critical bit */
	{ FLAG,			offsetof(private_cp_payload_t, critical) 				},	
 	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	/* Length of the whole CP payload*/
	{ PAYLOAD_LENGTH,		offsetof(private_cp_payload_t, payload_length) 	},	
	/* Proposals are stored in a proposal substructure, 
	   offset points to a linked_list_t pointer */
	{ U_INT_8,		offsetof(private_cp_payload_t, config_type)				},
	{ RESERVED_BYTE,0 														}, 
	{ RESERVED_BYTE,0														}, 
	{ RESERVED_BYTE,0														}, 	
	{ CONFIGURATION_ATTRIBUTES,	offsetof(private_cp_payload_t, attributes)	}
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

/**
 * Implementation of payload_t.verify.
 */
static status_t verify(private_cp_payload_t *this)
{
	status_t status = SUCCESS;
	iterator_t *iterator;

	iterator = this->attributes->create_iterator(this->attributes,TRUE);
	
	while(iterator->has_next(iterator))
	{
		configuration_attribute_t *attribute;
		iterator->current(iterator,(void **)&attribute);
		status = attribute->payload_interface.verify(&(attribute->payload_interface));
		if (status != SUCCESS)
		{
			break;
		}
	}
	
	iterator->destroy(iterator);
	return status;
}

/**
 * Implementation of payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_cp_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = cp_payload_encodings;
	*rule_count = sizeof(cp_payload_encodings) / sizeof(encoding_rule_t);
}

/**
 * Implementation of payload_t.get_type.
 */
static payload_type_t get_type(private_cp_payload_t *this)
{
	return CONFIGURATION;
}

/**
 * Implementation of payload_t.get_next_type.
 */
static payload_type_t get_next_type(private_cp_payload_t *this)
{
	return (this->next_payload);
}

/**
 * Implementation of payload_t.set_next_type.
 */
static void set_next_type(private_cp_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
}

/**
 * Implementation of payload_t.get_length.
 */
static size_t get_length(private_cp_payload_t *this)
{
	this->compute_length(this);
	return this->payload_length;
}

/**
 * Implementation of cp_payload_t.create_configuration_attribute_iterator.
 */
static iterator_t *create_configuration_attribute_iterator (private_cp_payload_t *this,bool forward)
{
	return this->attributes->create_iterator(this->attributes,forward);
}

/**
 * Implementation of cp_payload_t.add_proposal_substructure.
 */
static void add_configuration_attribute (private_cp_payload_t *this,configuration_attribute_t *attribute)
{
	this->attributes->insert_last(this->attributes,(void *) attribute);
	this->compute_length(this);
}

/**
 * Implementation of cp_payload_t.set_config_type.
 */
static void set_config_type (private_cp_payload_t *this,config_type_t config_type)
{
	this->config_type = config_type;
}

/**
 * Implementation of cp_payload_t.get_config_type.
 */
static config_type_t get_config_type (private_cp_payload_t *this)
{
	return this->config_type;
}

/**
 * Implementation of private_cp_payload_t.compute_length.
 */
static void compute_length (private_cp_payload_t *this)
{
	iterator_t *iterator;
	size_t length = CP_PAYLOAD_HEADER_LENGTH;
	iterator = this->attributes->create_iterator(this->attributes,TRUE);
	while (iterator->has_next(iterator))
	{
		payload_t *current_attribute;
		iterator->current(iterator,(void **) &current_attribute);
		length += current_attribute->get_length(current_attribute);
	}
	iterator->destroy(iterator);
	
	this->payload_length = length;
}

/**
 * Implementation of payload_t.destroy and cp_payload_t.destroy.
 */
static status_t destroy(private_cp_payload_t *this)
{
	/* all attributes are getting destroyed */ 
	while (this->attributes->get_count(this->attributes) > 0)
	{
		configuration_attribute_t *current_attribute;
		this->attributes->remove_last(this->attributes,(void **)&current_attribute);
		current_attribute->destroy(current_attribute);
	}
	this->attributes->destroy(this->attributes);
	
	free(this);
	
	return SUCCESS;
}

/*
 * Described in header.
 */
cp_payload_t *cp_payload_create()
{
	private_cp_payload_t *this = malloc_thing(private_cp_payload_t);
	
	/* public interface */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (void (*) (payload_t *))destroy;
	
	/* public functions */
	this->public.create_configuration_attribute_iterator = (iterator_t* (*) (cp_payload_t *,bool)) create_configuration_attribute_iterator;
	this->public.add_configuration_attribute = (void (*) (cp_payload_t *,configuration_attribute_t *)) add_configuration_attribute;
	this->public.set_config_type = (void (*) (cp_payload_t *, config_type_t)) set_config_type;
	this->public.get_config_type = (config_type_t (*) (cp_payload_t *)) get_config_type;
	this->public.destroy = (void (*) (cp_payload_t *)) destroy;
	
	
	/* private functions */
	this->compute_length = compute_length;
	
	/* set default values of the fields */
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = CP_PAYLOAD_HEADER_LENGTH;

	this->attributes = linked_list_create();
	return (&(this->public));
}
