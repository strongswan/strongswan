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
#include <utils/identification.h>
#include <utils/logger.h>

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
	 * Lifetime of IKE_SA in milliseconds.
	 */
	u_int32_t ike_sa_lifetime;
	
	/**
	 * list for all proposals
	 */
	linked_list_t *proposals;
	
	/**
	 * list for traffic selectors for initiator site
	 */
	linked_list_t *ts_initiator;
	
	/**
	 * list for traffic selectors for responder site
	 */
	linked_list_t *ts_responder;

	/**
	 * get_traffic_selectors for both
	 */
	size_t (*get_traffic_selectors) (private_sa_config_t *,linked_list_t*,traffic_selector_t**[]);

	/**
	 * select_traffic_selectors for both
	 */
	size_t (*select_traffic_selectors) (private_sa_config_t *,linked_list_t*,traffic_selector_t*[],size_t,traffic_selector_t**[]);
};

/**
 * Implementation of sa_config_t.get_my_id
 */
static identification_t *get_my_id(private_sa_config_t *this)
{
	return this->my_id;
}

/**
 * Implementation of sa_config_t.get_other_id
 */
static identification_t *get_other_id(private_sa_config_t *this)
{
	return this->other_id;
}

/**
 * Implementation of sa_config_t.get_auth_method.
 */
static auth_method_t get_auth_method(private_sa_config_t *this)
{
	return this->auth_method;
}

/**
 * Implementation of sa_config_t.get_ike_sa_lifetime.
 */
static u_int32_t get_ike_sa_lifetime (private_sa_config_t *this)
{
	return this->ike_sa_lifetime;
}

/**
 * Implementation of sa_config_t.get_traffic_selectors_initiator
 */
static size_t get_traffic_selectors_initiator(private_sa_config_t *this, traffic_selector_t **traffic_selectors[])
{
	return this->get_traffic_selectors(this, this->ts_initiator, traffic_selectors);
}

/**
 * Implementation of sa_config_t.get_traffic_selectors_responder
 */
static size_t get_traffic_selectors_responder(private_sa_config_t *this, traffic_selector_t **traffic_selectors[])
{
	return this->get_traffic_selectors(this, this->ts_responder, traffic_selectors);
}

/**
 * Implementation of private_sa_config_t.get_traffic_selectors
 */
static size_t get_traffic_selectors(private_sa_config_t *this, linked_list_t *ts_list, traffic_selector_t **traffic_selectors[])
{
	iterator_t *iterator;
	traffic_selector_t *current_ts;
	int counter = 0;
	*traffic_selectors = allocator_alloc(sizeof(traffic_selector_t*) * ts_list->get_count(ts_list));
	
	/* copy all ts from the list in an array */
	iterator = ts_list->create_iterator(ts_list, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current_ts);
		*((*traffic_selectors) + counter) = current_ts->clone(current_ts);
		counter++;
	}
	iterator->destroy(iterator);
	return counter;	
}

/**
 * Implementation of private_sa_config_t.select_traffic_selectors_initiator
 */
static size_t select_traffic_selectors_initiator(private_sa_config_t *this,traffic_selector_t *supplied[], size_t count, traffic_selector_t **selected[])
{
	return this->select_traffic_selectors(this, this->ts_initiator, supplied, count, selected);
}

/**
 * Implementation of private_sa_config_t.select_traffic_selectors_responder
 */
static size_t select_traffic_selectors_responder(private_sa_config_t *this,traffic_selector_t *supplied[], size_t count, traffic_selector_t **selected[])
{
	return this->select_traffic_selectors(this, this->ts_responder, supplied, count, selected);
}
/**
 * Implementation of private_sa_config_t.select_traffic_selectors
 */
static size_t select_traffic_selectors(private_sa_config_t *this, linked_list_t *ts_list, traffic_selector_t *supplied[], size_t count, traffic_selector_t **selected[])
{
	iterator_t *iterator;
	traffic_selector_t *current_ts;
	int i, counter = 0;
	*selected = allocator_alloc(sizeof(traffic_selector_t*) * ts_list->get_count(ts_list));
	
	/* iterate over all stored proposals */
	iterator = ts_list->create_iterator(ts_list, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current_ts);
		for (i = 0; i < count; i++)
		{
			traffic_selector_t *new_ts;
			/* compare it */
			new_ts = current_ts->get_subset(current_ts, supplied[i]);
			/* match ? */
			if (new_ts)
			{
				*((*selected) + counter) = new_ts;
				counter++;
			}
		}
	}
	iterator->destroy(iterator);
	
	/* free unused space */
	*selected = allocator_realloc(*selected, sizeof(traffic_selector_t) * counter);
	return counter;	
}

/**
 * Implementation of sa_config_t.get_proposal_iterator
 */
static linked_list_t *get_proposals(private_sa_config_t *this)
{
	return this->proposals;
}

/**
 * Implementation of sa_config_t.select_proposal
 */
static child_proposal_t *select_proposal(private_sa_config_t *this, linked_list_t *proposals)
{
	iterator_t *stored_iter, *supplied_iter;
	child_proposal_t *stored, *supplied, *selected;
	
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
 * Implementation of sa_config_t.add_traffic_selector_initiator
 */
static void add_traffic_selector_initiator(private_sa_config_t *this, traffic_selector_t *traffic_selector)
{
	/* clone ts, and add*/
	this->ts_initiator->insert_last(this->ts_initiator, (void*)traffic_selector->clone(traffic_selector));
}

/**
 * Implementation of sa_config_t.add_traffic_selector_responder
 */
static void add_traffic_selector_responder(private_sa_config_t *this, traffic_selector_t *traffic_selector)
{
	/* clone ts, and add*/
	this->ts_responder->insert_last(this->ts_responder, (void*)traffic_selector->clone(traffic_selector));
}

/**
 * Implementation of sa_config_t.add_proposal
 */
static void add_proposal(private_sa_config_t *this, child_proposal_t *proposal)
{
	this->proposals->insert_last(this->proposals, (void*)proposal);
}

/**
 * Implements sa_config_t.destroy.
 */
static status_t destroy(private_sa_config_t *this)
{	
	child_proposal_t *proposal;
	traffic_selector_t *traffic_selector;
	
	
	/* delete proposals */
	while(this->proposals->remove_last(this->proposals, (void**)&proposal) == SUCCESS)
	{
		proposal->destroy(proposal);
	}
	this->proposals->destroy(this->proposals);
	
	/* delete traffic selectors */
	while(this->ts_initiator->remove_last(this->ts_initiator, (void**)&traffic_selector) == SUCCESS)
	{
		traffic_selector->destroy(traffic_selector);
	}
	this->ts_initiator->destroy(this->ts_initiator);
	
	/* delete traffic selectors */
	while(this->ts_responder->remove_last(this->ts_responder, (void**)&traffic_selector) == SUCCESS)
	{
		traffic_selector->destroy(traffic_selector);
	}
	this->ts_responder->destroy(this->ts_responder);
	
	/* delete ids */
	this->my_id->destroy(this->my_id);
	this->other_id->destroy(this->other_id);
	
	allocator_free(this);
	return SUCCESS;
}

/*
 * Described in header-file
 */
sa_config_t *sa_config_create(id_type_t my_id_type, char *my_id, id_type_t other_id_type, char *other_id, auth_method_t auth_method, u_int32_t ike_sa_lifetime)
{
	private_sa_config_t *this = allocator_alloc_thing(private_sa_config_t);

	/* public functions */
	this->public.get_my_id = (identification_t*(*)(sa_config_t*))get_my_id;
	this->public.get_other_id = (identification_t*(*)(sa_config_t*))get_other_id;
	this->public.get_auth_method = (auth_method_t(*)(sa_config_t*))get_auth_method;
	this->public.get_ike_sa_lifetime = (u_int32_t(*)(sa_config_t*))get_ike_sa_lifetime;
	this->public.get_traffic_selectors_initiator = (size_t(*)(sa_config_t*,traffic_selector_t**[]))get_traffic_selectors_initiator;
	this->public.select_traffic_selectors_initiator = (size_t(*)(sa_config_t*,traffic_selector_t*[],size_t,traffic_selector_t**[]))select_traffic_selectors_initiator;
	this->public.get_traffic_selectors_responder = (size_t(*)(sa_config_t*,traffic_selector_t**[]))get_traffic_selectors_responder;
	this->public.select_traffic_selectors_responder = (size_t(*)(sa_config_t*,traffic_selector_t*[],size_t,traffic_selector_t**[]))select_traffic_selectors_responder;
	this->public.get_proposals = (linked_list_t*(*)(sa_config_t*))get_proposals;
	this->public.select_proposal = (child_proposal_t*(*)(sa_config_t*,linked_list_t*))select_proposal;
	this->public.add_traffic_selector_initiator = (void(*)(sa_config_t*,traffic_selector_t*))add_traffic_selector_initiator;
	this->public.add_traffic_selector_responder = (void(*)(sa_config_t*,traffic_selector_t*))add_traffic_selector_responder;
	this->public.add_proposal = (void(*)(sa_config_t*,child_proposal_t*))add_proposal;
	this->public.destroy = (void(*)(sa_config_t*))destroy;
	
	/* apply init values */
	this->my_id = identification_create_from_string(my_id_type, my_id);
	if (this->my_id == NULL)
	{
		allocator_free(this);
		return NULL;
	}
	this->other_id = identification_create_from_string(other_id_type, other_id);
	if (this->my_id == NULL)
	{
		this->other_id->destroy(this->other_id);
		allocator_free(this);
		return NULL;
	}
	
	/* init private members*/
	this->select_traffic_selectors = select_traffic_selectors;
	this->get_traffic_selectors = get_traffic_selectors;
	this->proposals = linked_list_create();
	this->ts_initiator = linked_list_create();
	this->ts_responder = linked_list_create();
	this->auth_method = auth_method;
	this->ike_sa_lifetime = ike_sa_lifetime;

	return (&this->public);
}
