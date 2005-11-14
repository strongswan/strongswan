/**
 * @file proposal_substructure.h
 * 
 * @brief Declaration of the class proposal_substructure_t. 
 * 
 * An object of this type represents an IKEv2 PROPOSAL Substructure and contains transforms.
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

#include "proposal_substructure.h"

#include "encodings.h"
#include "../types.h"
#include "../utils/allocator.h"
#include "../utils/linked_list.h"

/**
 * Private data of an proposal_substructure_t' Object
 * 
 */
typedef struct private_proposal_substructure_s private_proposal_substructure_t;

struct private_proposal_substructure_s {
	/**
	 * public proposal_substructure_t interface
	 */
	proposal_substructure_t public;
	
	/**
	 * next payload type
	 */
	u_int8_t  next_payload;

	
	/**
	 * Length of this payload
	 */
	u_int16_t proposal_length;
	
	
	/**
	 * Proposal number
	 */
	u_int8_t	 proposal_number;
	
	/**
	 * Protocol ID
	 */
	u_int8_t protocol_id;

	/**
	 * SPI size of the following SPI
	 */
 	u_int8_t  spi_size;

	/**
	 * Number of transforms
	 */
 	u_int8_t  transforms_count;
 	
 	/**
 	 * SPI is stored as chunk
 	 */
 	chunk_t spi;
 	
 	/**
 	 * Transforms are stored in a linked_list_t
 	 */
	linked_list_t * transforms;
};

/**
 * Encoding rules to parse or generate a Proposal substructure
 * 
 * The defined offsets are the positions in a object of type 
 * private_proposal_substructure_t.
 * 
 */
encoding_rule_t proposal_substructure_encodings[] = {
 	/* 1 Byte next payload type, stored in the field next_payload */
	{ U_INT_8,			offsetof(private_proposal_substructure_t, next_payload) 			},
	/* Reserved Byte is skipped */
	{ RESERVED_BYTE,		0																},	
	/* Length of the whole SA payload*/
	{ PAYLOAD_LENGTH,		offsetof(private_proposal_substructure_t, proposal_length) 	},	
	/* proposal number is a number of 8 bit */
	{ U_INT_8,				offsetof(private_proposal_substructure_t, proposal_number) 	},	
	/* protocol ID is a number of 8 bit */
	{ U_INT_8,				offsetof(private_proposal_substructure_t, protocol_id)		},	
	/* SPI Size has its own type */
	{ SPI_SIZE,				offsetof(private_proposal_substructure_t, spi_size)			},	
	/* Number of transforms is a number of 8 bit */
	{ U_INT_8,				offsetof(private_proposal_substructure_t, transforms_count)	},	
	/* SPI is a chunk of variable size*/
	{ SPI,					offsetof(private_proposal_substructure_t, spi)				},	
	/* Transforms are stored in a transform substructure, 
	   offset points to a linked_list_t pointer */
	{ TRANSFORMS,				offsetof(private_proposal_substructure_t, transforms) 	}
};

/**
 * Implements payload_t's and proposal_substructure_t's destroy function.
 * See #payload_s.destroy or proposal_substructure_s.destroy for description.
 */
static status_t destroy(private_proposal_substructure_t *this)
{
	/* all proposals are getting destroyed */ 
	while (this->transforms->get_count(this->transforms) > 0)
	{
		transforms_substructure_t *current_transform;
		if (this->transforms->remove_last(this->transforms,(void **)&current_transform) != SUCCESS)
		{
			break;
		}
		current_transform->destroy(current_transform);
	}
	this->transforms->destroy(this->transforms);
	
	if (this->spi.ptr != NULL)
	{
		allocator_free(this->spi.ptr);
	}
	
	allocator_free(this);
	
	return SUCCESS;
}

/**
 * Implements payload_t's get_encoding_rules function.
 * See #payload_s.get_encoding_rules for description.
 */
static status_t get_encoding_rules(private_proposal_substructure_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = proposal_substructure_encodings;
	*rule_count = sizeof(proposal_substructure_encodings) / sizeof(encoding_rule_t);
	
	return SUCCESS;
}

/**
 * Implements payload_t's get_type function.
 * See #payload_s.get_type for description.
 */
static payload_type_t get_type(private_proposal_substructure_t *this)
{
	return PROPOSAL_SUBSTRUCTURE;
}

/**
 * Implements payload_t's get_next_type function.
 * See #payload_s.get_next_type for description.
 */
static payload_type_t get_next_type(private_proposal_substructure_t *this)
{
	return (this->next_payload);
}

/**
 * Implements payload_t's get_length function.
 * See #payload_s.get_length for description.
 */
static size_t get_length(private_proposal_substructure_t *this)
{
	return this->proposal_length;
}

/*
 * Described in header
 */
proposal_substructure_t *proposal_substructure_create()
{
	private_proposal_substructure_t *this = allocator_alloc_thing(private_proposal_substructure_t);
	if (this == NULL)
	{
		return NULL;	
	}	
	
	this->public.payload_interface.get_encoding_rules = (status_t (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (status_t (*) (payload_t *))destroy;
	this->public.destroy = (status_t (*) (proposal_substructure_t *)) destroy;
	
	/* set default values of the fields */
	this->next_payload = NO_PAYLOAD;
	this->proposal_length = 0;
	this->proposal_number = 0;
	this->protocol_id = 0;
	this->transforms_count = 0;
	this->spi_size = 0;
	this->spi.ptr = NULL;
	this->spi.len = 0;

	this->transforms = linked_list_create();
	
	if (this->transforms == NULL)
	{
		allocator_free(this);
		return NULL;
	}
	return (&(this->public));
}


