/**
 * @file sa_config.c
 * 
 * @brief Implementation of sa_config_t.
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

#include "sa_config.h"

#include <utils/linked_list.h>
#include <utils/allocator.h>

typedef struct private_sa_config_t private_sa_config_t;

/**
 * Private data of an sa_config_t object
 */
struct private_sa_config_t {

	/**
	 * Public part
	 */
	sa_config_t public;
	
	/**
	 * id to use to identify us
	 */
	identification_t *my_id;
	
	/**
	 * allowed id for other
	 */
	identification_t *other_id;
	
	/**
	 * authentification method to use
	 */
	auth_method_t auth_method;
	
	/**
	 * list for all proposals
	 */
	linked_list_t *proposals;
	
	/**
	 * list for traffic selectors
	 */
	linked_list_t *ts;
	
	/**
	 * compare two traffic_selectors for equality
	 */
	bool (*traffic_selector_equals) (private_sa_config_t *this, traffic_selector_t *first,  traffic_selector_t *second);

	/**
	 * compare two proposals for equality
	 */
	bool (*proposal_equals) (private_sa_config_t *this, child_proposal_t *first, child_proposal_t *second);
};


static identification_t *get_my_id(private_sa_config_t *this)
{
	return this->my_id;
}

static identification_t *get_other_id(private_sa_config_t *this)
{
	return this->other_id;
}

static auth_method_t get_auth_method(private_sa_config_t *this)
{
	return this->auth_method;
}
	
static size_t get_traffic_selectors(private_sa_config_t *this, traffic_selector_t **traffic_selectors)
{
	iterator_t *iterator;
	traffic_selector_t *current_ts;
	int counter = 0;
	*traffic_selectors = allocator_alloc(sizeof(traffic_selector_t) * this->ts->get_count(this->ts));
	
	/* copy all ts from the list in an array */
	iterator = this->ts->create_iterator(this->ts, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current_ts);
		memcpy((*traffic_selectors) + counter, current_ts, sizeof(traffic_selector_t));
		counter++;
	}
	iterator->destroy(iterator);
	return counter;	
}

static size_t select_traffic_selectors(private_sa_config_t *this, traffic_selector_t *supplied, size_t count, traffic_selector_t **selected)
{
	iterator_t *iterator;
	traffic_selector_t *current_ts;
	int i, counter = 0;
	*selected = allocator_alloc(sizeof(traffic_selector_t) * this->ts->get_count(this->ts));
	
	/* iterate over all stored proposals */
	iterator = this->ts->create_iterator(this->ts, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current_ts);
		for (i = 0; i < count; i++)
		{
			/* copy if a supplied one is equal to ours */
			if (this->traffic_selector_equals(this, &(supplied[i]), current_ts))
			{
				memcpy((*selected) + counter, current_ts, sizeof(traffic_selector_t));
				counter++;
			}
		}
	}
	iterator->destroy(iterator);
	
	/* free unused space */
	*selected = allocator_realloc(*selected, sizeof(traffic_selector_t) * counter);
	return counter;	
}
	
static size_t get_proposals(private_sa_config_t *this, child_proposal_t **proposals)
{
	iterator_t *iterator;
	child_proposal_t *current_proposal;
	int counter = 0;
	*proposals = allocator_alloc(sizeof(child_proposal_t) * this->proposals->get_count(this->proposals));
	
	/* copy all proposals from the list in an array */
	iterator = this->proposals->create_iterator(this->proposals, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current_proposal);
		memcpy((*proposals) + counter, current_proposal, sizeof(child_proposal_t));
		counter++;
	}
	iterator->destroy(iterator);
	return counter;	
}

static child_proposal_t *select_proposal(private_sa_config_t *this, child_proposal_t *supplied, size_t count)
{
	iterator_t *iterator;
	child_proposal_t *current_proposal, *selected_proposal = NULL;
	int i;
	
	/* iterate over all stored proposals */
	iterator = this->proposals->create_iterator(this->proposals, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current_proposal);
		/* copy and break if a proposal matches */
		for (i = 0; i < count; i++)
		{
			if (this->proposal_equals(this, &(supplied[i]), current_proposal))
			{
				selected_proposal = allocator_alloc(sizeof(child_proposal_t));
				memcpy(selected_proposal, current_proposal, sizeof(child_proposal_t));
				break;
			}
		}
	}
	iterator->destroy(iterator);

	return selected_proposal;
}

static bool traffic_selector_equals(private_sa_config_t *this, traffic_selector_t *first,  traffic_selector_t *second)
{
	if (first->protocol == second->protocol)
	{
		if (first->begin->equals(first->begin, second->begin) &&
			first->end->equals(first->end, second->end))
		{
			return TRUE;
				
		}
	}
	return FALSE;	
}

static bool proposal_equals(private_sa_config_t *this, child_proposal_t *first, child_proposal_t *second)
{
	if (first->ah.is_set && second->ah.is_set)
	{
		if ((first->ah.integrity_algorithm != second->ah.integrity_algorithm) ||
			(first->ah.key_size != second->ah.key_size))
		{
			return FALSE;
		}
	}
	else
	{
		return FALSE;	
	}
	if (first->esp.is_set && second->esp.is_set)
	{
		if ((first->esp.encryption_algorithm != second->esp.encryption_algorithm) ||
			(first->esp.key_size != second->esp.key_size))
		{
			return FALSE;
		}
	}
	else
	{
		return FALSE;	
	}
	return TRUE;
}
	
static void add_traffic_selector(private_sa_config_t *this, traffic_selector_t *traffic_selector)
{
	this->ts->insert_last(this->ts, (void*)traffic_selector);
}

static void add_proposal(private_sa_config_t *this, child_proposal_t *proposal)
{
	this->proposals->insert_last(this->ts, (void*)proposal);
}

/**
 * Implements sa_config_t.destroy.
 */
static status_t destroy(private_sa_config_t *this)
{	
	child_proposal_t *proposal;
	traffic_selector_t *traffic_selector;
	
	/* delete proposals */
	while(this->proposals->get_count(this->proposals) > 0)
	{
		this->proposals->remove_last(this->proposals, (void**)&proposal);
		allocator_free(proposal);
	}
	this->proposals->destroy(this->proposals);
	
	/* delete traffic selectors */
	while(this->ts->get_count(this->ts) > 0)
	{
		this->ts->remove_last(this->ts, (void**)&traffic_selector);
		allocator_free(traffic_selector);
	}
	this->ts->destroy(this->ts);
	
	allocator_free(this);
	return SUCCESS;
}

/*
 * Described in header-file
 */
sa_config_t *sa_config_create()
{
	private_sa_config_t *this = allocator_alloc_thing(private_sa_config_t);

	/* public functions */
	this->public.get_my_id = (identification_t(*)(sa_config_t*))get_my_id;
	this->public.get_other_id = (identification_t(*)(sa_config_t*))get_other_id;
	this->public.get_auth_method = (auth_method_t(*)(sa_config_t*))get_auth_method;
	this->public.get_traffic_selectors = (size_t(*)(sa_config_t*,traffic_selector_t**))get_traffic_selectors;
	this->public.select_traffic_selectors = (size_t(*)(sa_config_t*,traffic_selector_t*,size_t,traffic_selector_t**))select_traffic_selectors;
	this->public.get_proposals = (size_t(*)(sa_config_t*,child_proposal_t**))get_proposals;
	this->public.select_proposal = (child_proposal_t*(*)(sa_config_t*,child_proposal_t*,size_t))select_proposal;
	this->public.add_traffic_selector = (void(*)(sa_config_t*,traffic_selector_t*))add_traffic_selector;
	this->public.add_proposal = (void(*)(sa_config_t*,child_proposal_t*))add_proposal;
	this->public.destroy = (void(*)(sa_config_t*))destroy;

	/* private variables */
	this->proposal_equals = proposal_equals;
	this->traffic_selector_equals = traffic_selector_equals;
	this->proposals = linked_list_create();
	this->ts = linked_list_create();

	return (&this->public);
}
