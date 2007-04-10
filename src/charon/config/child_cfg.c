/**
 * @file child_cfg.c
 * 
 * @brief Implementation of child_cfg_t.
 * 
 */

/*
 * Copyright (C) 2005-2007 Martin Willi
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


#include "child_cfg.h"

#include <daemon.h>

ENUM(mode_names, MODE_TRANSPORT, MODE_BEET,
	"TRANSPORT",
	"TUNNEL",
	"2",
	"3",
	"BEET",
);

typedef struct private_child_cfg_t private_child_cfg_t;

/**
 * Private data of an child_cfg_t object
 */
struct private_child_cfg_t {

	/**
	 * Public part
	 */
	child_cfg_t public;
	
	/**
	 * Number of references hold by others to this child_cfg
	 */
	refcount_t refcount;
	
	/**
	 * Name of the child_cfg, used to query it
	 */
	char *name;
	
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
	 * updown script
	 */
	char *updown;
	
	/**
	 * allow host access
	 */
	bool hostaccess;
	
	/**
	 * Mode to propose for a initiated CHILD: tunnel/transport
	 */
	mode_t mode;
	
	/**
	 * Time before an SA gets invalid
	 */
	u_int32_t lifetime;
	
	/**
	 * Time before an SA gets rekeyed
	 */
	u_int32_t rekeytime;
	
	/**
	 * Time, which specifies the range of a random value
	 * substracted from rekeytime.
	 */
	u_int32_t jitter;
};

/**
 * Implementation of child_cfg_t.get_name
 */
static char *get_name(private_child_cfg_t *this)
{
	return this->name;
}

/**
 * Implementation of child_cfg_t.add_proposal
 */
static void add_proposal(private_child_cfg_t *this, proposal_t *proposal)
{
	this->proposals->insert_last(this->proposals, proposal);
}

/**
 * Implementation of child_cfg_t.get_proposals
 */
static linked_list_t* get_proposals(private_child_cfg_t *this)
{
	iterator_t *iterator;
	proposal_t *current;
	linked_list_t *proposals = linked_list_create();
	
	iterator = this->proposals->create_iterator(this->proposals, TRUE);
	while (iterator->iterate(iterator, (void**)&current))
	{
		current = current->clone(current);
		proposals->insert_last(proposals, current);
	}
	iterator->destroy(iterator);
	
	return proposals;
}

/**
 * Implementation of child_cfg_t.get_name
 */
static proposal_t* select_proposal(private_child_cfg_t*this, linked_list_t *proposals)
{
	iterator_t *stored_iter, *supplied_iter;
	proposal_t *stored, *supplied, *selected = NULL;
	
	stored_iter = this->proposals->create_iterator(this->proposals, TRUE);
	supplied_iter = proposals->create_iterator(proposals, TRUE);
	
	/* compare all stored proposals with all supplied. Stored ones are preferred. */
	while (stored_iter->iterate(stored_iter, (void**)&stored))
	{
		supplied_iter->reset(supplied_iter);
		while (supplied_iter->iterate(supplied_iter, (void**)&supplied))
		{
			selected = stored->select(stored, supplied);
			if (selected)
			{
				break;
			}
		}
		if (selected)
		{
			break;
		}
	}
	stored_iter->destroy(stored_iter);
	supplied_iter->destroy(supplied_iter);
	return selected;
}

/**
 * Implementation of child_cfg_t.get_name
 */
static void add_traffic_selector(private_child_cfg_t *this, bool local,
								 traffic_selector_t *ts)
{
	if (local)
	{
		this->my_ts->insert_last(this->my_ts, ts);
	}
	else
	{
		this->other_ts->insert_last(this->other_ts, ts);
	}
}

/**
 * Implementation of child_cfg_t.get_name
 */
static linked_list_t* get_traffic_selectors(private_child_cfg_t *this, bool local,
											linked_list_t *supplied,
											host_t *host)
{
	iterator_t *i1, *i2;
	traffic_selector_t *ts1, *ts2, *selected;
	linked_list_t *result = linked_list_create();
	
	if (local)
	{
		i1 = this->my_ts->create_iterator(this->my_ts, TRUE);
	}
	else
	{
		i1 = this->other_ts->create_iterator(this->other_ts, FALSE);
	}
	
	/* no list supplied, just fetch the stored traffic selectors */
	if (supplied == NULL)
	{
		while (i1->iterate(i1, (void**)&ts1))
		{
			/* we make a copy of the TS, this allows us to update dynamic TS' */
			ts1 = ts1->clone(ts1);
			if (host)
			{
				ts1->set_address(ts1, host);
			}
			result->insert_last(result, ts1);
		}
		i1->destroy(i1);
	}
	else
	{
		DBG2(DBG_CFG, "selecting traffic selectors");
		i2 = supplied->create_iterator(supplied, TRUE);
		/* iterate over all stored selectors */
		while (i1->iterate(i1, (void**)&ts1))
		{
			/* we make a copy of the TS, as we have to update dynamic TS' */
			ts1 = ts1->clone(ts1);
			if (host)
			{
				ts1->set_address(ts1, host);
			}
			
			i2->reset(i2);
			/* iterate over all supplied traffic selectors */
			while (i2->iterate(i2, (void**)&ts2))
			{
				DBG2(DBG_CFG, "stored %R <=> %R received", ts1, ts2);
				selected = ts1->get_subset(ts1, ts2);
				if (selected)
				{
					result->insert_last(result, selected);
					DBG2(DBG_CFG, "found traffic selector for %s: %R", 
						 local ? "us" : "other", selected);
				}
			}
			ts1->destroy(ts1);
		}
		i1->destroy(i1);
		i2->destroy(i2);
	}
	
	/* remove any redundant traffic selectors in the list */
	i1 = result->create_iterator(result, TRUE);
	i2 = result->create_iterator(result, TRUE);
	while (i1->iterate(i1, (void**)&ts1))
	{
		while (i2->iterate(i2, (void**)&ts2))
		{
			if (ts1 != ts2)
			{
				if (ts2->is_contained_in(ts2, ts1))
				{
					i2->remove(i2);
					ts2->destroy(ts2);
					i1->reset(i1);
					break;
				}
				if (ts1->is_contained_in(ts1, ts2))
				{
					i1->remove(i1);
					ts1->destroy(ts1);
					i2->reset(i2);
					break;
				}
			}
		}
	}
	i1->destroy(i1);
	i2->destroy(i2);
	
	return result;
}

/**
 * Implementation of child_cfg_t.get_name
 */
static char* get_updown(private_child_cfg_t *this)
{
	return this->updown;
}

/**
 * Implementation of child_cfg_t.get_name
 */
static bool get_hostaccess(private_child_cfg_t *this)
{
	return this->hostaccess;
}

/**
 * Implementation of child_cfg_t.get_name
 */
static u_int32_t get_lifetime(private_child_cfg_t *this, bool rekey)
{
	if (rekey)
	{
		if (this->jitter == 0)
		{
			return this->rekeytime;
		}
		return this->rekeytime - (random() % this->jitter);
	}
	return this->lifetime;
}

/**
 * Implementation of child_cfg_t.get_name
 */
static mode_t get_mode(private_child_cfg_t *this)
{
	return this->mode;
}

/**
 * Implementation of child_cfg_t.get_name
 */
static void get_ref(private_child_cfg_t *this)
{
	ref_get(&this->refcount);
}

/**
 * Implements child_cfg_t.destroy.
 */
static void destroy(private_child_cfg_t *this)
{
	if (ref_put(&this->refcount))
	{
		this->proposals->destroy_offset(this->proposals, offsetof(proposal_t, destroy));
		this->my_ts->destroy_offset(this->my_ts, offsetof(traffic_selector_t, destroy));
		this->other_ts->destroy_offset(this->other_ts, offsetof(traffic_selector_t, destroy));
		if (this->updown)
		{
			free(this->updown);
		}
		free(this->name);
		free(this);
	}
}

/*
 * Described in header-file
 */
child_cfg_t *child_cfg_create(char *name, u_int32_t lifetime,
							  u_int32_t rekeytime, u_int32_t jitter,
							  char *updown, bool hostaccess, mode_t mode)
{
	private_child_cfg_t *this = malloc_thing(private_child_cfg_t);

	/* public functions */
	this->public.get_name = (char* (*) (child_cfg_t*))get_name;
	this->public.add_traffic_selector = (void (*)(child_cfg_t*,bool,traffic_selector_t*))add_traffic_selector;
	this->public.get_traffic_selectors = (linked_list_t*(*)(child_cfg_t*,bool,linked_list_t*,host_t*))get_traffic_selectors;
	this->public.add_proposal = (void (*) (child_cfg_t*,proposal_t*))add_proposal;
	this->public.get_proposals = (linked_list_t* (*) (child_cfg_t*))get_proposals;
	this->public.select_proposal = (proposal_t* (*) (child_cfg_t*,linked_list_t*))select_proposal;
	this->public.get_updown = (char* (*) (child_cfg_t*))get_updown;
	this->public.get_hostaccess = (bool (*) (child_cfg_t*))get_hostaccess;
	this->public.get_mode = (mode_t (*) (child_cfg_t *))get_mode;
	this->public.get_lifetime = (u_int32_t (*) (child_cfg_t *,bool))get_lifetime;
	this->public.get_ref = (void (*) (child_cfg_t*))get_ref;
	this->public.destroy = (void (*) (child_cfg_t*))destroy;
	
	/* apply init values */
	this->name = strdup(name);
	this->lifetime = lifetime;
	this->rekeytime = rekeytime;
	this->jitter = jitter;
	this->updown = updown ? strdup(updown) : NULL;
	this->hostaccess = hostaccess;
	this->mode = mode;
	
	/* initialize private members*/
	this->refcount = 1;
	this->proposals = linked_list_create();
	this->my_ts = linked_list_create();
	this->other_ts = linked_list_create();

	return &this->public;
}
