/**
 * @file sa_payload.c
 * 
 * @brief Implementation of sa_payload_t.
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

#include <encoding/payloads/encodings.h>
#include <utils/allocator.h>
#include <utils/linked_list.h>


typedef struct private_sa_payload_t private_sa_payload_t;

/**
 * Private data of an sa_payload_t object.
 * 
 */
struct private_sa_payload_t {
	/**
	 * Public sa_payload_t interface.
	 */
	sa_payload_t public;
	
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
	 * Proposals in this payload are stored in a linked_list_t.
	 */
	linked_list_t * proposals;
	
	/**
	 * @brief Computes the length of this payload.
	 *
	 * @param this 	calling private_sa_payload_t object
	 */
	void (*compute_length) (private_sa_payload_t *this);
};

/**
 * Encoding rules to parse or generate a IKEv2-SA Payload
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

/*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                                                               !
      ~                          <Proposals>                          ~
      !                                                               !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/**
 * Implementation of payload_t.verify.
 */
static status_t verify(private_sa_payload_t *this)
{
	int proposal_number = 1;
	status_t status = SUCCESS;
	iterator_t *iterator;
	bool first = TRUE;
	
	if (this->critical)
	{
		/* critical bit set! */
		return FAILED;
	}

	/* check proposal numbering */		
	iterator = this->proposals->create_iterator(this->proposals,TRUE);
	
	while(iterator->has_next(iterator))
	{
		proposal_substructure_t *current_proposal;
		iterator->current(iterator,(void **)&current_proposal);
		if (current_proposal->get_proposal_number(current_proposal) > proposal_number)
		{
			if (first) 
			{
				/* first number must be 1 */
				status = FAILED;
				break;
			}
			
			if (current_proposal->get_proposal_number(current_proposal) != (proposal_number + 1))
			{
				/* must be only one more then previous proposal */
				status = FAILED;
				break;
			}
		}
		else if (current_proposal->get_proposal_number(current_proposal) < proposal_number)
		{
			/* must not be smaller then proceeding one */
			status = FAILED;
			break;
		}
		
		status = current_proposal->payload_interface.verify(&(current_proposal->payload_interface));
		if (status != SUCCESS)
		{
			break;
		}
		first = FALSE;
	}
	
	iterator->destroy(iterator);
	return status;
}


/**
 * Implementation of payload_t.destroy and sa_payload_t.destroy.
 */
static status_t destroy(private_sa_payload_t *this)
{
	/* all proposals are getting destroyed */ 
	while (this->proposals->get_count(this->proposals) > 0)
	{
		proposal_substructure_t *current_proposal;
		this->proposals->remove_last(this->proposals,(void **)&current_proposal);
		current_proposal->destroy(current_proposal);
	}
	this->proposals->destroy(this->proposals);
	
	allocator_free(this);
	
	return SUCCESS;
}

/**
 * Implementation of payload_t.get_encoding_rules.
 */
static void get_encoding_rules(private_sa_payload_t *this, encoding_rule_t **rules, size_t *rule_count)
{
	*rules = sa_payload_encodings;
	*rule_count = sizeof(sa_payload_encodings) / sizeof(encoding_rule_t);
}

/**
 * Implementation of payload_t.get_type.
 */
static payload_type_t get_type(private_sa_payload_t *this)
{
	return SECURITY_ASSOCIATION;
}

/**
 * Implementation of payload_t.get_next_type.
 */
static payload_type_t get_next_type(private_sa_payload_t *this)
{
	return (this->next_payload);
}

/**
 * Implementation of payload_t.set_next_type.
 */
static void set_next_type(private_sa_payload_t *this,payload_type_t type)
{
	this->next_payload = type;
}

/**
 * Implementation of payload_t.get_length.
 */
static size_t get_length(private_sa_payload_t *this)
{
	this->compute_length(this);
	return this->payload_length;
}

/**
 * Implementation of sa_payload_t.create_proposal_substructure_iterator.
 */
static iterator_t *create_proposal_substructure_iterator (private_sa_payload_t *this,bool forward)
{
	return this->proposals->create_iterator(this->proposals,forward);
}

/**
 * Implementation of sa_payload_t.add_proposal_substructure.
 */
static void add_proposal_substructure (private_sa_payload_t *this,proposal_substructure_t *proposal)
{
	status_t status;
	if (this->proposals->get_count(this->proposals) > 0)
	{
		proposal_substructure_t *last_proposal;
		status = this->proposals->get_last(this->proposals,(void **) &last_proposal);
		/* last transform is now not anymore last one */
		last_proposal->set_is_last_proposal(last_proposal,FALSE);
	}
	proposal->set_is_last_proposal(proposal,TRUE);
	
	this->proposals->insert_last(this->proposals,(void *) proposal);
	this->compute_length(this);
}

/**
 * Implementation of sa_payload_t.add_proposal.
 */
static void add_proposal(private_sa_payload_t *this, proposal_t *proposal)
{
	proposal_substructure_t *substructure;
	protocol_id_t proto[2];
	u_int i;
	
	/* build the substructures for every protocol */
	proposal->get_protocols(proposal, proto);
	for (i = 0; i<2; i++)
	{
		if (proto[i] != UNDEFINED_PROTOCOL_ID)
		{
			substructure = proposal_substructure_create_from_proposal(proposal, proto[i]);
			add_proposal_substructure(this, substructure);
		}
	}
}

/**
 * Implementation of sa_payload_t.get_proposals.
 */
static linked_list_t *get_proposals(private_sa_payload_t *this)
{
	int proposal_struct_number = 0;
	iterator_t *iterator;
	proposal_t *proposal;
	linked_list_t *proposal_list;
	
	/* this list will hold our proposals */
	proposal_list = linked_list_create();
	
	/* iterate over structures, one OR MORE structures will result in a proposal */
	iterator = this->proposals->create_iterator(this->proposals,TRUE);
	while (iterator->has_next(iterator))
	{
		proposal_substructure_t *proposal_struct;
		iterator->current(iterator,(void **)&(proposal_struct));
		
		if (proposal_struct->get_proposal_number(proposal_struct) > proposal_struct_number)
		{
			/* here starts a new proposal, create a new one and add it to the list */
			proposal_struct_number = proposal_struct->get_proposal_number(proposal_struct);
			proposal = proposal_create(proposal_struct_number);
			proposal_list->insert_last(proposal_list, proposal);
		}
		/* proposal_substructure_t does the dirty work and builds up the proposal */
		proposal_struct->add_to_proposal(proposal_struct, proposal);
	}
	iterator->destroy(iterator);
	return proposal_list;
}

/**
 * Implementation of private_sa_payload_t.compute_length.
 */
static void compute_length (private_sa_payload_t *this)
{
	iterator_t *iterator;
	size_t length = SA_PAYLOAD_HEADER_LENGTH;
	iterator = this->proposals->create_iterator(this->proposals,TRUE);
	while (iterator->has_next(iterator))
	{
		payload_t *current_proposal;
		iterator->current(iterator,(void **) &current_proposal);
		length += current_proposal->get_length(current_proposal);
	}
	iterator->destroy(iterator);
	
	this->payload_length = length;
}

/*
 * Described in header.
 */
sa_payload_t *sa_payload_create()
{
	private_sa_payload_t *this = allocator_alloc_thing(private_sa_payload_t);
	
	/* public interface */
	this->public.payload_interface.verify = (status_t (*) (payload_t *))verify;
	this->public.payload_interface.get_encoding_rules = (void (*) (payload_t *, encoding_rule_t **, size_t *) ) get_encoding_rules;
	this->public.payload_interface.get_length = (size_t (*) (payload_t *)) get_length;
	this->public.payload_interface.get_next_type = (payload_type_t (*) (payload_t *)) get_next_type;
	this->public.payload_interface.set_next_type = (void (*) (payload_t *,payload_type_t)) set_next_type;
	this->public.payload_interface.get_type = (payload_type_t (*) (payload_t *)) get_type;
	this->public.payload_interface.destroy = (void (*) (payload_t *))destroy;
	
	/* public functions */
	this->public.create_proposal_substructure_iterator = (iterator_t* (*) (sa_payload_t *,bool)) create_proposal_substructure_iterator;
	this->public.add_proposal_substructure = (void (*) (sa_payload_t *,proposal_substructure_t *)) add_proposal_substructure;
	this->public.get_proposals = (linked_list_t* (*) (sa_payload_t *)) get_proposals;
	this->public.destroy = (void (*) (sa_payload_t *)) destroy;
	
	/* private functions */
	this->compute_length = compute_length;
	
	/* set default values of the fields */
	this->critical = SA_PAYLOAD_CRITICAL_FLAG;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = SA_PAYLOAD_HEADER_LENGTH;

	this->proposals = linked_list_create();
	return (&(this->public));
}

/*
 * Described in header.
 */
sa_payload_t *sa_payload_create_from_proposal_list(linked_list_t *proposals)
{
	iterator_t *iterator;
	proposal_t *proposal;
	sa_payload_t *sa_payload = sa_payload_create();
	
	/* add every payload from the list */
	iterator = proposals->create_iterator(proposals, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&proposal);
		add_proposal((private_sa_payload_t*)sa_payload, proposal);
	}
	iterator->destroy(iterator);
	
	return sa_payload;
}

/*
 * Described in header.
 */
sa_payload_t *sa_payload_create_from_proposal(proposal_t *proposal)
{
	sa_payload_t *sa_payload = sa_payload_create();
	
	add_proposal((private_sa_payload_t*)sa_payload, proposal);
	
	return sa_payload;
}
