/**
 * @file policy.c
 * 
 * @brief Implementation of policy_t.
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

#include <time.h>
#include <string.h>
#include <unistd.h>

#include "policy.h"

#include <utils/linked_list.h>
#include <utils/identification.h>
#include <utils/logger_manager.h>

/** 
 * String mappings for auth_method_t.
 */
static const char *const auth_method_name[] = {
	"RSA signature",
	"pre-shared key",
	"DSS signature"
};

enum_names auth_method_names =
    { RSA_DIGITAL_SIGNATURE, DSS_DIGITAL_SIGNATURE, auth_method_name, NULL };

/** 
 * String mappings for dpd_action_t.
 */
static const char *const dpd_action_name[] = {
	"DPD_NONE",
	"DPD_CLEAR",
	"DPD_ROUTE",
	"DPD_RESTART"
};

enum_names dpd_action_names =
    { DPD_NONE, DPD_RESTART, dpd_action_name, NULL };

typedef struct private_policy_t private_policy_t;

/**
 * Private data of an policy_t object
 */
struct private_policy_t {

	/**
	 * Public part
	 */
	policy_t public;
	
	/**
	 * Number of references hold by others to this policy
	 */
	refcount_t refcount;
	
	/**
	 * Name of the policy, used to query it
	 */
	char *name;
	
	/**
	 * id to use to identify us
	 */
	identification_t *my_id;
	
	/**
	 * allowed id for other
	 */
	identification_t *other_id;
	
	/**
	 * Method to use for own authentication data
	 */
	auth_method_t auth_method;
	
	/**
	 * we have a cert issued by this CA
	 */
	identification_t *my_ca;
	
	/**
	 * we require the other end to have a cert issued by this CA
	 */
	identification_t *other_ca;
	
	/**
	 * updown script
	 */
	char *updown;
	
	/**
	 * allow host access
	 */
	bool hostaccess;
	
	/**
	 * list for all proposals
	 */
	linked_list_t *proposals;
	
	/**
	 * list for traffic selectors for my site
	 */
	linked_list_t *my_ts;
	
	/**
	 * list for traffic selectors for others site
	 */
	linked_list_t *other_ts;
	
	/**
	 * Time before an SA gets invalid
	 */
	u_int32_t soft_lifetime;
	
	/**
	 * Time before an SA gets rekeyed
	 */
	u_int32_t hard_lifetime;
	
	/**
	 * Time, which specifies the range of a random value
	 * substracted from soft_lifetime.
	 */
	u_int32_t jitter;
	
	/**
	 * What to do with an SA when other peer seams to be dead?
	 */
	bool dpd_action;
	
	/**
	 * logger
	 */
	logger_t *logger;
};

/**
 * Implementation of policy_t.get_name
 */
static char *get_name(private_policy_t *this)
{
	return this->name;
}

/**
 * Implementation of policy_t.get_my_id
 */
static identification_t *get_my_id(private_policy_t *this)
{
	return this->my_id;
}

/**
 * Implementation of policy_t.get_other_id
 */
static identification_t *get_other_id(private_policy_t *this)
{
	return this->other_id;
}

/**
 * Implementation of connection_t.auth_method_t.
 */
static auth_method_t get_auth_method(private_policy_t *this)
{
	return this->auth_method;
}

/**
 * Get traffic selectors, with wildcard-address update
 */
static linked_list_t *get_traffic_selectors(private_policy_t *this, linked_list_t *list, host_t *host)
{
	iterator_t *iterator;
	traffic_selector_t *current;
	linked_list_t *result = linked_list_create();
	
	iterator = list->create_iterator(list, TRUE);
	
	while (iterator->iterate(iterator, (void**)&current))
	{
		/* we make a copy of the TS, this allows us to update wildcard
		 * addresses in it. We won't pollute the shared policy. */
		current = current->clone(current);
		current->update_address_range(current, host);
		
		result->insert_last(result, (void*)current);
	}
	iterator->destroy(iterator);
	return result;
}

/**
 * Implementation of policy_t.get_my_traffic_selectors
 */
static linked_list_t *get_my_traffic_selectors(private_policy_t *this, host_t *me)
{
	return get_traffic_selectors(this, this->my_ts, me);
}

/**
 * Implementation of policy_t.get_other_traffic_selectors
 */
static linked_list_t *get_other_traffic_selectors(private_policy_t *this, host_t *other)
{
	return get_traffic_selectors(this, this->other_ts, other);
}

/**
 * Narrow traffic selectors, with wildcard-address update in "stored".
 */
static linked_list_t *select_traffic_selectors(private_policy_t *this,
											   linked_list_t *stored,
											   linked_list_t *supplied,
											   host_t *host)
{
	iterator_t *supplied_iter, *stored_iter;
	traffic_selector_t *supplied_ts, *stored_ts, *selected_ts;
	linked_list_t *selected = linked_list_create();
	
	this->logger->log(this->logger, CONTROL|LEVEL1,
					  "selecting traffic selectors for %s host",
					  stored == this->my_ts ? "local" : "remote");
	
	stored_iter = stored->create_iterator(stored, TRUE);
	supplied_iter = supplied->create_iterator(supplied, TRUE);
	
	/* iterate over all stored selectors */
	while (stored_iter->iterate(stored_iter, (void**)&stored_ts))
	{
		/* we make a copy of the TS, this allows us to update wildcard
		 * addresses in it. We won't pollute the shared policy. */
		stored_ts = stored_ts->clone(stored_ts);
		stored_ts->update_address_range(stored_ts, host);
		
		supplied_iter->reset(supplied_iter);
		/* iterate over all supplied traffic selectors */
		while (supplied_iter->iterate(supplied_iter, (void**)&supplied_ts))
		{
			this->logger->log(this->logger, CONTROL|LEVEL2,
							  "  stored %s <=> %s received",
							  stored_ts->get_string(stored_ts), 
							  supplied_ts->get_string(supplied_ts));
			
			selected_ts = stored_ts->get_subset(stored_ts, supplied_ts);
			if (selected_ts)
			{
				/* got a match, add to list */
				selected->insert_last(selected, (void*)selected_ts);
				
				this->logger->log(this->logger, CONTROL|LEVEL1, "    got a match: %s",
								  selected_ts->get_string(selected_ts));
			}
		}
		stored_ts->destroy(stored_ts);
	}
	stored_iter->destroy(stored_iter);
	supplied_iter->destroy(supplied_iter);
	
	return selected;
}

/**
 * Implementation of private_policy_t.select_my_traffic_selectors
 */
static linked_list_t *select_my_traffic_selectors(private_policy_t *this,
												  linked_list_t *supplied,
												  host_t *me)
{
	return select_traffic_selectors(this, this->my_ts, supplied, me);
}

/**
 * Implementation of private_policy_t.select_other_traffic_selectors
 */
static linked_list_t *select_other_traffic_selectors(private_policy_t *this,
		 											 linked_list_t *supplied,
													 host_t* other)
{
	return select_traffic_selectors(this, this->other_ts, supplied, other);
}

/**
 * Implementation of policy_t.get_proposal_iterator
 */
static linked_list_t *get_proposals(private_policy_t *this)
{
	iterator_t *iterator;
	proposal_t *current;
	linked_list_t *proposals = linked_list_create();
	
	iterator = this->proposals->create_iterator(this->proposals, TRUE);
	while (iterator->iterate(iterator, (void**)&current))
	{
		current = current->clone(current);
		proposals->insert_last(proposals, (void*)current);
	}
	iterator->destroy(iterator);
	
	return proposals;
}

/**
 * Implementation of policy_t.select_proposal
 */
static proposal_t *select_proposal(private_policy_t *this, linked_list_t *proposals)
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
 * Implementation of policy_t.add_authorities
 */
static void add_authorities(private_policy_t *this, identification_t *my_ca, identification_t *other_ca)
{
	this->my_ca = my_ca;
	this->other_ca = other_ca;
}

/**
 * Implementation of policy_t.get_updown
 */
static char* get_updown(private_policy_t *this)
{
	return this->updown;
}

/**
 * Implementation of policy_t.get_hostaccess
 */
static bool get_hostaccess(private_policy_t *this)
{
	return this->hostaccess;
}

/**
 * Implements policy_t.get_dpd_action
 */
static dpd_action_t get_dpd_action(private_policy_t *this)
{
	return this->dpd_action;
}


/**
 * Implementation of policy_t.add_my_traffic_selector
 */
static void add_my_traffic_selector(private_policy_t *this, traffic_selector_t *traffic_selector)
{
	this->my_ts->insert_last(this->my_ts, (void*)traffic_selector);
}

/**
 * Implementation of policy_t.add_other_traffic_selector
 */
static void add_other_traffic_selector(private_policy_t *this, traffic_selector_t *traffic_selector)
{
	this->other_ts->insert_last(this->other_ts, (void*)traffic_selector);
}

/**
 * Implementation of policy_t.add_proposal
 */
static void add_proposal(private_policy_t *this, proposal_t *proposal)
{
	this->proposals->insert_last(this->proposals, (void*)proposal);
}

/**
 * Implementation of policy_t.get_soft_lifetime
 */
static u_int32_t get_soft_lifetime(private_policy_t *this)
{
	if (this->jitter == 0)
	{
		return this->soft_lifetime ;
	}
	return this->soft_lifetime - (random() % this->jitter);
}

/**
 * Implementation of policy_t.get_hard_lifetime
 */
static u_int32_t get_hard_lifetime(private_policy_t *this)
{
	return this->hard_lifetime;
}

/**
 * Implements policy_t.get_ref.
 */
static void get_ref(private_policy_t *this)
{
	ref_get(&this->refcount);
}

/**
 * Implements policy_t.destroy.
 */
static void destroy(private_policy_t *this)
{
	if (ref_put(&this->refcount))
	{
		proposal_t *proposal;
		traffic_selector_t *traffic_selector;
		
		/* delete proposals */
		while(this->proposals->remove_last(this->proposals, (void**)&proposal) == SUCCESS)
		{
			proposal->destroy(proposal);
		}
		this->proposals->destroy(this->proposals);
		
		/* delete traffic selectors */
		while(this->my_ts->remove_last(this->my_ts, (void**)&traffic_selector) == SUCCESS)
		{
			traffic_selector->destroy(traffic_selector);
		}
		this->my_ts->destroy(this->my_ts);
		
		/* delete traffic selectors */
		while(this->other_ts->remove_last(this->other_ts, (void**)&traffic_selector) == SUCCESS)
		{
			traffic_selector->destroy(traffic_selector);
		}
		this->other_ts->destroy(this->other_ts);
		
		/* delete certification authorities */
		if (this->my_ca)
		{
			this->my_ca->destroy(this->my_ca);
		}
		if (this->other_ca)
		{
			this->other_ca->destroy(this->other_ca);
		}
		
		/* delete updown script */
		if (this->updown)
		{
			free(this->updown);
		}
		
		/* delete ids */
		this->my_id->destroy(this->my_id);
		this->other_id->destroy(this->other_id);
		
		free(this->name);
		free(this);
	}
}

/*
 * Described in header-file
 */
policy_t *policy_create(char *name, identification_t *my_id, identification_t *other_id,
						auth_method_t auth_method,
						u_int32_t hard_lifetime, u_int32_t soft_lifetime, 
						u_int32_t jitter, char *updown, bool hostaccess,
						dpd_action_t dpd_action)
{
	private_policy_t *this = malloc_thing(private_policy_t);

	/* public functions */
	this->public.get_name = (char* (*) (policy_t*))get_name;
	this->public.get_my_id = (identification_t* (*) (policy_t*))get_my_id;
	this->public.get_other_id = (identification_t* (*) (policy_t*))get_other_id;
	this->public.get_auth_method = (auth_method_t (*) (policy_t*)) get_auth_method;
	this->public.get_my_traffic_selectors = (linked_list_t* (*) (policy_t*,host_t*))get_my_traffic_selectors;
	this->public.get_other_traffic_selectors = (linked_list_t* (*) (policy_t*,host_t*))get_other_traffic_selectors;
	this->public.select_my_traffic_selectors = (linked_list_t* (*) (policy_t*,linked_list_t*,host_t*))select_my_traffic_selectors;
	this->public.select_other_traffic_selectors = (linked_list_t* (*) (policy_t*,linked_list_t*,host_t*))select_other_traffic_selectors;
	this->public.get_proposals = (linked_list_t* (*) (policy_t*))get_proposals;
	this->public.select_proposal = (proposal_t* (*) (policy_t*,linked_list_t*))select_proposal;
	this->public.add_my_traffic_selector = (void (*) (policy_t*,traffic_selector_t*))add_my_traffic_selector;
	this->public.add_other_traffic_selector = (void (*) (policy_t*,traffic_selector_t*))add_other_traffic_selector;
	this->public.add_proposal = (void (*) (policy_t*,proposal_t*))add_proposal;
	this->public.add_authorities = (void (*) (policy_t*,identification_t*,identification_t*))add_authorities;
	this->public.get_updown = (char* (*) (policy_t*))get_updown;
	this->public.get_hostaccess = (bool (*) (policy_t*))get_hostaccess;
	this->public.get_dpd_action = (dpd_action_t (*) (policy_t*))get_dpd_action;
	this->public.get_soft_lifetime = (u_int32_t (*) (policy_t *))get_soft_lifetime;
	this->public.get_hard_lifetime = (u_int32_t (*) (policy_t *))get_hard_lifetime;
	this->public.get_ref = (void (*) (policy_t*))get_ref;
	this->public.destroy = (void (*) (policy_t*))destroy;
	
	/* apply init values */
	this->name = strdup(name);
	this->my_id = my_id;
	this->other_id = other_id;
	this->auth_method = auth_method;
	this->hard_lifetime = hard_lifetime;
	this->soft_lifetime = soft_lifetime;
	this->jitter = jitter;
	this->updown = (updown == NULL) ? NULL : strdup(updown);
	this->hostaccess = hostaccess;
	this->dpd_action = dpd_action;
	
	/* initialize private members*/
	this->refcount = 1;
	this->my_ca = NULL;
	this->other_ca = NULL;
	this->proposals = linked_list_create();
	this->my_ts = linked_list_create();
	this->other_ts = linked_list_create();
	this->logger = logger_manager->get_logger(logger_manager, CONFIG);

	return &this->public;
}
