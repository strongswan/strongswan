/**
 * @file init_config.c
 * 
 * @brief Implementation of init_config_t.
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

#include "init_config.h"

#include <utils/allocator.h>
#include <utils/linked_list.h>

typedef struct private_init_config_t private_init_config_t;

/**
 * Private data of an init_config_t object
 */
struct private_init_config_t {

	/**
	 * Public part
	 */
	init_config_t public;

	/**
	 * Host information of my host.
	 */
	host_t *my_host;

	/**
	 * Host information of other host.
	 */	
	host_t *other_host;
	
	/**
	 * Supported proposals
	 */
	linked_list_t *proposals;
};

/**
 * Implementation of init_config_t.get_my_host.
 */
static host_t * get_my_host (private_init_config_t *this)
{
	return this->my_host->clone(this->my_host);
}

/**
 * Implementation of init_config_t.get_other_host.
 */
static host_t * get_other_host (private_init_config_t *this)
{
	return this->other_host->clone(this->other_host);
}

/**
 * Implementation of init_config_t.get_dh_group_number.
 */
static diffie_hellman_group_t get_dh_group_number (private_init_config_t *this,size_t priority)
{
	ike_proposal_t *ike_proposal;
	
	if ((this->proposals->get_count(this->proposals) == 0) || (this->proposals->get_count(this->proposals) < priority))
	{
		return MODP_UNDEFINED;
	}
	
	this->proposals->get_at_position(this->proposals,(priority -1),(void **) &ike_proposal);
	
	return (ike_proposal->diffie_hellman_group);
}

/**
 * Implementation of init_config_t.get_proposals.
 */
static size_t get_proposals (private_init_config_t *this,ike_proposal_t **proposals)
{
	iterator_t *iterator;
	ike_proposal_t *current_proposal;
	int i = 0;
	ike_proposal_t *proposal_array;
	
	proposal_array = allocator_alloc(this->proposals->get_count(this->proposals) * sizeof(ike_proposal_t));
		
	iterator = this->proposals->create_iterator(this->proposals,TRUE);
	
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator,(void **) &current_proposal);
		proposal_array[i] = (*current_proposal);
		i++;
	}
	iterator->destroy(iterator);
	
	*proposals = proposal_array;
	return this->proposals->get_count(this->proposals);
}
	
/**
 * Implementation of init_config_t.select_proposal.
 */
static status_t select_proposal (private_init_config_t *this, ike_proposal_t *proposals, size_t proposal_count, ike_proposal_t *selected_proposal)
{
	iterator_t * my_iterator;
	int i;
	ike_proposal_t *my_current_proposal;

	my_iterator = this->proposals->create_iterator(this->proposals,TRUE);

	
	for (i = 0; i < proposal_count; i++)
	{
		my_iterator->reset(my_iterator);
		while (my_iterator->has_next(my_iterator))
		{
			my_iterator->current(my_iterator,(void **) &my_current_proposal);
		
			if (memcmp(my_current_proposal,&proposals[i],sizeof(ike_proposal_t)) == 0)
			{
				/* found a matching proposal */
				*selected_proposal = *my_current_proposal;
				my_iterator->destroy(my_iterator);
				return SUCCESS;
			}
		}				
	}
	
	my_iterator->destroy(my_iterator);
	return NOT_FOUND;
}

/**
 * Implementation of init_config_t.destroy.
 */
static void add_proposal (private_init_config_t *this,size_t priority, ike_proposal_t proposal)
{
	ike_proposal_t * new_proposal = allocator_alloc(sizeof(ike_proposal_t));
	
	*new_proposal = proposal;
	 
	
	if (priority > this->proposals->get_count(this->proposals))
	{
		this->proposals->insert_last(this->proposals,new_proposal);
		return;
	}
	
	this->proposals->insert_at_position(this->proposals,(priority - 1),new_proposal);
}

/**
 * Implementation of init_config_t.destroy.
 */
static void destroy (private_init_config_t *this)
{
	ike_proposal_t *proposal;
	
	while (this->proposals->get_count(this->proposals) > 0)
	{
		this->proposals->remove_first(this->proposals,(void **) &proposal);
		allocator_free(proposal);
	}
	this->proposals->destroy(this->proposals);
	
	this->my_host->destroy(this->my_host);
	this->other_host->destroy(this->other_host);
	
	allocator_free(this);
}

/**
 * Described in header.
 */
init_config_t * init_config_create(char * my_ip, char *other_ip, u_int16_t my_port, u_int16_t other_port)
{
	private_init_config_t *this = allocator_alloc_thing(private_init_config_t);

	/* public functions */
	this->public.get_my_host = (host_t*(*)(init_config_t*))get_my_host;
	this->public.get_other_host = (host_t*(*)(init_config_t*))get_other_host;
	this->public.get_dh_group_number = (diffie_hellman_group_t (*)(init_config_t*,size_t))get_dh_group_number;
	this->public.get_proposals = (size_t(*)(init_config_t*,ike_proposal_t**))get_proposals;
	this->public.select_proposal = (status_t(*)(init_config_t*,ike_proposal_t*,size_t,ike_proposal_t*))select_proposal;
	this->public.add_proposal = (void(*)(init_config_t*, size_t, ike_proposal_t)) add_proposal;
	this->public.destroy = (void(*)(init_config_t*))destroy;
	
	/* private variables */
	this->my_host = host_create(AF_INET,my_ip, my_port);
	this->other_host = host_create(AF_INET,other_ip, other_port);
	
	this->proposals = linked_list_create();

	return (&this->public);
}
