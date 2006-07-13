/**
 * @file sa_payload.c
 * 
 * @brief Implementation of sa_payload_t.
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

#include "sa_payload.h"

#include <encoding/payloads/encodings.h>
#include <utils/linked_list.h>
#include <utils/logger_manager.h>


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
	 * Logger for error handling
	 */
	logger_t *logger;
	
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
	int expected_number = 1, current_number;
	status_t status = SUCCESS;
	iterator_t *iterator;
	bool first = TRUE;

	/* check proposal numbering */		
	iterator = this->proposals->create_iterator(this->proposals,TRUE);
	
	while(iterator->has_next(iterator))
	{
		proposal_substructure_t *current_proposal;
		iterator->current(iterator,(void **)&current_proposal);
		current_number = current_proposal->get_proposal_number(current_proposal);
		if (current_number > expected_number)
		{
			if (first) 
			{
				this->logger->log(this->logger, ERROR, "first proposal is not proposal #1");
				status = FAILED;
				break;
			}
			
			if (current_number != (expected_number + 1))
			{
				this->logger->log(this->logger, ERROR, "proposal number is %d, excepted %d or %d",
								  current_number, expected_number, expected_number + 1);
				status = FAILED;
				break;
			}
		}
		else if (current_number < expected_number)
		{
			/* must not be smaller then proceeding one */
			this->logger->log(this->logger, ERROR, "proposal number smaller than that of previous proposal");
			status = FAILED;
			break;
		}
		
		status = current_proposal->payload_interface.verify(&(current_proposal->payload_interface));
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, ERROR, "PROPOSAL_SUBSTRUCTURE verification failed");
			break;
		}
		first = FALSE;
		expected_number = current_number;
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
	
	free(this);
	
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
static void add_proposal_substructure(private_sa_payload_t *this,proposal_substructure_t *proposal)
{
	status_t status;
	u_int proposal_count = this->proposals->get_count(this->proposals);
	
	if (proposal_count > 0)
	{
		proposal_substructure_t *last_proposal;
		status = this->proposals->get_last(this->proposals,(void **) &last_proposal);
		/* last transform is now not anymore last one */
		last_proposal->set_is_last_proposal(last_proposal, FALSE);
	}
	proposal->set_is_last_proposal(proposal, TRUE);
	proposal->set_proposal_number(proposal, proposal_count + 1);
	this->proposals->insert_last(this->proposals,(void *) proposal);
	this->compute_length(this);
}

/**
 * Implementation of sa_payload_t.add_proposal.
 */
static void add_proposal(private_sa_payload_t *this, proposal_t *proposal)
{
	proposal_substructure_t *substructure;
	
	substructure = proposal_substructure_create_from_proposal(proposal);
	add_proposal_substructure(this, substructure);
}

/**
 * Implementation of sa_payload_t.get_proposals.
 */
static linked_list_t *get_proposals(private_sa_payload_t *this)
{
	int struct_number = 0;
	int ignore_struct_number = 0;
	iterator_t *iterator;
	linked_list_t *proposal_list;
	
	/* this list will hold our proposals */
	proposal_list = linked_list_create();
	
	/* we do not support proposals split up to two proposal substructures, as
	 * AH+ESP bundles are not supported in RFC4301 anymore.
	 * To handle such structures safely, we just skip proposals with multiple
	 * protocols.
	 */
	iterator = this->proposals->create_iterator(this->proposals, TRUE);
	while (iterator->has_next(iterator))
	{
		proposal_t *proposal;
		proposal_substructure_t *proposal_struct;
		
		iterator->current(iterator, (void **)&proposal_struct);
		/* check if a proposal has a single protocol */
		if (proposal_struct->get_proposal_number(proposal_struct) == struct_number)
		{
			if (ignore_struct_number < struct_number)
			{
				/* remova an already added, if first of series */
				proposal_list->remove_last(proposal_list, (void**)&proposal);
				proposal->destroy(proposal);
				ignore_struct_number = struct_number;
			}
			continue;
		}
		struct_number++;
		proposal = proposal_struct->get_proposal(proposal_struct);
		if (proposal)
		{
			proposal_list->insert_last(proposal_list, proposal);
		}
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
	private_sa_payload_t *this = malloc_thing(private_sa_payload_t);
	
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
	this->public.add_proposal = (void (*) (sa_payload_t*,proposal_t*))add_proposal;
	this->public.get_proposals = (linked_list_t* (*) (sa_payload_t *)) get_proposals;
	this->public.destroy = (void (*) (sa_payload_t *)) destroy;
	
	/* private functions */
	this->compute_length = compute_length;
	
	/* set default values of the fields */
	this->critical = FALSE;
	this->next_payload = NO_PAYLOAD;
	this->payload_length = SA_PAYLOAD_HEADER_LENGTH;
	this->logger = logger_manager->get_logger(logger_manager, PARSER);

	this->proposals = linked_list_create();
	return &this->public;
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
