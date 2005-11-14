/**
 * @file sa_payload.h
 * 
 * @brief Declaration of the class sa_payload_t. 
 * 
 * An object of this type represents an IKEv2 SA-Payload and contains proposal 
 * substructures.
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

#include "sa_payload.h"

#include "encodings.h"
#include "../utils/allocator.h"
#include "../utils/linked_list.h"


/**
 * Private data of an sa_payload_t' Object
 * 
 */
typedef struct private_sa_payload_s private_sa_payload_t;

struct private_sa_payload_s {
	/**
	 * public sa_payload_t interface
	 */
	sa_payload_t public;
	
	/**
	 * next payload type
	 */
	u_int8_t  next_payload;

	/**
	 * Critical flag
	 */
	bool critical;
	
	/**
	 * Length of this payload
	 */
	u_int16_t payload_length;
	
	/**
	 * Proposals in this payload are stored in a linked_list_t
	 */
	linked_list_t * proposals;
};

/**
 * Encoding rules to parse or generate a IKEv2-Header
 * 
 * The defined offsets are the positions in a object of type 
 * private_sa_payload_t.
 * 
 */
encoding_rule_t sa_payload_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,		offsetof(private_sa_payload_t, next_payload) 			},
	/* the critical bit */
	{ FLAG,			offsetof(private_sa_payload_t, critical) 				},	
 	/* 7 Bit reserved bits, nowhere stored */
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	{ RESERVED_BIT,	0 														}, 
	/* Length of the whole SA payload*/
	{ PAYLOAD_LENGTH,		offsetof(private_sa_payload_t, payload_length) 	},	
	/* Proposals are stored in a proposal substructure, 
	   offset points to a linked_list_t pointer */
	{ PROPOSALS,		offsetof(private_sa_payload_t, proposals) 				}
};

/**
 * Implements payload_t's and sa_payload_t's destroy function.
 * See #payload_s.destroy or sa_payload_s.destroy for description.
 */
static status_t destroy(private_sa_payload_t *this)
{
	/* all proposals are getting destroyed */ 
	while (this->proposals->get_count(this->proposals) > 0)
	{
		proposal_substructure_t *current_proposal;
		if (this->proposals->remove_last(this->proposals,(void **)&current_proposal) != SUCCESS)
		{
			break;
		}
		current_proposal->destroy(current_proposal);
	}
	this->proposals->destroy(this->proposals);
	
	allocator_free(this);
	
	return SUCCESS;
}

/**
 * Implements payload_t's get_encoding_rules function.
 * See #payload_s.get_encoding_rules for description.
 */
static status_t get_encoding_rules(private_sa_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = sa_payload_encodings;
	*rule_count = sizeof(sa_payload_encodings) / sizeof(encoding_rule_t);
	
	return SUCCESS;
}

/**
 * Implements payload_t's get_type function.
 * See #payload_s.get_type for description.
 */
static payload_type_t get_type(private_sa_payload_t *this)
{
	return SECURITY_ASSOCIATION;
}

/**
 * Implements payload_t's get_next_type function.
 * See #payload_s.get_next_type for description.
 */
static payload_type_t get_next_type(private_sa_payload_t *this)
{
	return (this->next_payload);
}

/**
 * Implements payload_t's get_length function.
 * See #payload_s.get_length for description.
 */
static size_t get_length(private_sa_payload_t *this)
{
	return this->payload_length;
}

/**
 * Implements sa_payload_t's create_proposal_substructure_iterator function.
 * See #sa_payload_s.create_proposal_substructure_iterator for description.
 */
static status_t create_proposal_substructure_iterator (private_sa_payload_t *this,linked_list_iterator_t **iterator,bool forward)
{
	return (this->proposals->create_iterator(this->proposals,iterator,forward));
}

/**
 * Implements sa_payload_t's add_proposal_substructure function.
 * See #sa_payload_s.add_proposal_substructure for description.
 */
static status_t add_proposal_substructure (private_sa_payload_t *this,proposal_substructure_t *proposal)
{
	return (this->proposals->insert_last(this->proposals,(void *) proposal));
}

/*
 * Described in header
 */
sa_payload_t *sa_payload_create()
{
	private_sa_payload_t *this = allocator_alloc_thing(private_sa_payload_t);
	if (this == NULL)
	{
		return NULL;	
	}	
	
	this->public.payload_interface.get_encoding_rules = (status_t (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (status_t (*) (payload_t *))destroy;
	this->public.create_proposal_substructure_iterator = (status_t (*) (sa_payload_t *,linked_list_iterator_t **,bool)) create_proposal_substructure_iterator;
	this->public.add_proposal_substructure = (status_t (*) (sa_payload_t *,proposal_substructure_t *)) add_proposal_substructure;
	this->public.destroy = (status_t (*) (sa_payload_t *)) destroy;
	
	/* set default values of the fields */
	this->critical = SA_PAYLOAD_CRITICAL_FLAG;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = SA_PAYLOAD_HEADER_LENGTH;

	this->proposals = linked_list_create();
	
	if (this->proposals == NULL)
	{
		allocator_free(this);
		return NULL;
	}
	return (&(this->public));
}


