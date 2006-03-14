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
#include <utils/logger.h>

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
	return this->my_host;
}

/**
 * Implementation of init_config_t.get_other_host.
 */
static host_t * get_other_host (private_init_config_t *this)
{
	return this->other_host;
}

/**
 * Implementation of init_config_t.get_my_host_clone.
 */
static host_t * get_my_host_clone (private_init_config_t *this)
{
	return this->my_host->clone(this->my_host);
}

/**
 * Implementation of init_config_t.get_other_host_clone.
 */
static host_t * get_other_host_clone (private_init_config_t *this)
{
	return this->other_host->clone(this->other_host);
}

/**
 * Implementation of init_config_t.get_proposals.
 */
static linked_list_t* get_proposals (private_init_config_t *this)
{
	return this->proposals;
}
	
/**
 * Implementation of init_config_t.select_proposal.
 */
static proposal_t *select_proposal(private_init_config_t *this, linked_list_t *proposals)
{
	iterator_t *stored_iter, *supplied_iter;
	proposal_t *stored, *supplied, *selected;
	
	stored_iter = this->proposals->create_iterator(this->proposals, TRUE);
	supplied_iter = proposals->create_iterator(proposals, TRUE);
	
	/* compare all stored proposals with all supplied. Stored ones are preferred. */
	while (stored_iter->has_next(stored_iter))
	{
		supplied_iter->reset(supplied_iter);
		stored_iter->current(stored_iter, (void**)&stored);

		while (supplied_iter->has_next(supplied_iter))
		{
			supplied_iter->current(supplied_iter, (void**)&supplied);
			selected = stored->select(stored, supplied);
			if (selected)
			{
				/* they match, return */
				stored_iter->destroy(stored_iter);
				supplied_iter->destroy(supplied_iter);
				return selected;
			}
		}
	}
	
	/* no proposal match :-(, will result in a NO_PROPOSAL_CHOSEN... */
	stored_iter->destroy(stored_iter);
	supplied_iter->destroy(supplied_iter);
	
	return NULL;
}

/**
 * Implementation of init_config_t.add_proposal.
 */
static void add_proposal (private_init_config_t *this, proposal_t *proposal)
{
	this->proposals->insert_last(this->proposals, proposal);
}

/**
 * Implementation of init_config_t.get_dh_group.
 */
static diffie_hellman_group_t get_dh_group(private_init_config_t *this)
{
	iterator_t *iterator;
	proposal_t *proposal;
	algorithm_t *algo;
	
	iterator = this->proposals->create_iterator(this->proposals, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&proposal);
		proposal->get_algorithm(proposal, IKE, DIFFIE_HELLMAN_GROUP, &algo);
		if (algo)
		{
			iterator->destroy(iterator);
			return algo->algorithm;
		}
	}
	iterator->destroy(iterator);
	return MODP_UNDEFINED;
}

/**
 * Implementation of init_config_t.check_dh_group.
 */
static bool check_dh_group(private_init_config_t *this, diffie_hellman_group_t dh_group)
{
	iterator_t *prop_iter, *alg_iter;
	proposal_t *proposal;
	algorithm_t *algo;
	
	prop_iter = this->proposals->create_iterator(this->proposals, TRUE);
	while (prop_iter->has_next(prop_iter))
	{
		prop_iter->current(prop_iter, (void**)&proposal);
		alg_iter = proposal->create_algorithm_iterator(proposal, IKE, DIFFIE_HELLMAN_GROUP);
		while (alg_iter->has_next(alg_iter))
		{
			alg_iter->current(alg_iter, (void**)&algo);
			if (algo->algorithm == dh_group)
			{
				prop_iter->destroy(prop_iter);
				alg_iter->destroy(alg_iter);
				return TRUE;
			}
		}
	}
	prop_iter->destroy(prop_iter);
	alg_iter->destroy(alg_iter);
	return FALSE;
}

/**
 * Implementation of init_config_t.destroy.
 */
static void destroy (private_init_config_t *this)
{
	proposal_t *proposal;
	
	while (this->proposals->remove_last(this->proposals, (void**)&proposal) == SUCCESS)
	{
		proposal->destroy(proposal);
	}
	this->proposals->destroy(this->proposals);
	
	this->my_host->destroy(this->my_host);
	this->other_host->destroy(this->other_host);
	allocator_free(this);
}

/**
 * Described in header.
 */
init_config_t * init_config_create(host_t *me, host_t *other)
{
	private_init_config_t *this = allocator_alloc_thing(private_init_config_t);

	/* public functions */
	this->public.get_my_host = (host_t*(*)(init_config_t*))get_my_host;
	this->public.get_other_host = (host_t*(*)(init_config_t*))get_other_host;
	this->public.get_my_host_clone = (host_t*(*)(init_config_t*))get_my_host_clone;
	this->public.get_other_host_clone = (host_t*(*)(init_config_t*))get_other_host_clone;
	this->public.get_proposals = (linked_list_t*(*)(init_config_t*))get_proposals;
	this->public.select_proposal = (proposal_t*(*)(init_config_t*,linked_list_t*))select_proposal;
	this->public.add_proposal = (void(*)(init_config_t*, proposal_t*)) add_proposal;
	this->public.get_dh_group = (diffie_hellman_group_t(*)(init_config_t*)) get_dh_group;
	this->public.check_dh_group = (bool(*)(init_config_t*,diffie_hellman_group_t)) check_dh_group;
	this->public.destroy = (void(*)(init_config_t*))destroy;
	
	/* private variables */
	this->my_host = me;
	this->other_host = other;
		
	this->proposals = linked_list_create();

	return (&this->public);
}
