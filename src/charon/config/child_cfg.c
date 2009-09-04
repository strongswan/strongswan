/*
 * Copyright (C) 2008-2009 Tobias Brunner
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

ENUM(action_names, ACTION_NONE, ACTION_RESTART,
	"clear",
	"hold",
	"restart",
);

ENUM_BEGIN(ipcomp_transform_names, IPCOMP_NONE, IPCOMP_NONE,
	"IPCOMP_NONE");
ENUM_NEXT(ipcomp_transform_names, IPCOMP_OUI, IPCOMP_LZJH, IPCOMP_NONE,
	"IPCOMP_OUI",
	"IPCOMP_DEFLATE",
	"IPCOMP_LZS",
	"IPCOMP_LZJH");
ENUM_END(ipcomp_transform_names, IPCOMP_LZJH);

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
	ipsec_mode_t mode;

	/**
	 * action to take on DPD
	 */
	action_t dpd_action;

	/**
	 * action to take on CHILD_SA close
	 */
	action_t close_action;

	/**
	 * CHILD_SA lifetime config
	 */
	lifetime_cfg_t lifetime;

	/**
	 * enable IPComp
	 */
	bool use_ipcomp;

	/**
	 * set up IPsec transport SA in MIPv6 proxy mode
	 */
	bool proxy_mode;

	/**
	 * enable installation and removal of kernel IPsec policies
	 */
	bool install_policy;
};

/**
 * Implementation of child_cfg_t.get_name.
 */
static char *get_name(private_child_cfg_t *this)
{
	return this->name;
}

/**
 * Implementation of child_cfg_t.add_proposal.
 */
static void add_proposal(private_child_cfg_t *this, proposal_t *proposal)
{
	this->proposals->insert_last(this->proposals, proposal);
}

/**
 * Implementation of child_cfg_t.get_proposals.
 */
static linked_list_t* get_proposals(private_child_cfg_t *this, bool strip_dh)
{
	enumerator_t *enumerator;
	proposal_t *current;
	linked_list_t *proposals = linked_list_create();

	enumerator = this->proposals->create_enumerator(this->proposals);
	while (enumerator->enumerate(enumerator, &current))
	{
		current = current->clone(current);
		if (strip_dh)
		{
			current->strip_dh(current);
		}
		proposals->insert_last(proposals, current);
	}
	enumerator->destroy(enumerator);

	return proposals;
}

/**
 * Implementation of child_cfg_t.select_proposal.
 */
static proposal_t* select_proposal(private_child_cfg_t*this,
								   linked_list_t *proposals, bool strip_dh)
{
	enumerator_t *stored_enum, *supplied_enum;
	proposal_t *stored, *supplied, *selected = NULL;

	stored_enum = this->proposals->create_enumerator(this->proposals);
	supplied_enum = proposals->create_enumerator(proposals);

	/* compare all stored proposals with all supplied. Stored ones are preferred. */
	while (stored_enum->enumerate(stored_enum, &stored))
	{
		stored = stored->clone(stored);
		while (supplied_enum->enumerate(supplied_enum, &supplied))
		{
			if (strip_dh)
			{
				stored->strip_dh(stored);
			}
			selected = stored->select(stored, supplied);
			if (selected)
			{
				DBG2(DBG_CFG, "received proposals: %#P", proposals);
				DBG2(DBG_CFG, "configured proposals: %#P", this->proposals);
				DBG2(DBG_CFG, "selected proposal: %P", selected);
				break;
			}
		}
		stored->destroy(stored);
		if (selected)
		{
			break;
		}
		supplied_enum->destroy(supplied_enum);
		supplied_enum = proposals->create_enumerator(proposals);
	}
	stored_enum->destroy(stored_enum);
	supplied_enum->destroy(supplied_enum);
	if (selected == NULL)
	{
		DBG1(DBG_CFG, "received proposals: %#P", proposals);
		DBG1(DBG_CFG, "configured proposals: %#P", this->proposals);
	}
	return selected;
}

/**
 * Implementation of child_cfg_t.add_traffic_selector.
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
 * Implementation of child_cfg_t.get_traffic_selectors.
 */
static linked_list_t* get_traffic_selectors(private_child_cfg_t *this, bool local,
											linked_list_t *supplied,
											host_t *host)
{
	enumerator_t *e1, *e2;
	traffic_selector_t *ts1, *ts2, *selected;
	linked_list_t *result = linked_list_create();

	if (local)
	{
		e1 = this->my_ts->create_enumerator(this->my_ts);
	}
	else
	{
		e1 = this->other_ts->create_enumerator(this->other_ts);
	}

	/* no list supplied, just fetch the stored traffic selectors */
	if (supplied == NULL)
	{
		DBG2(DBG_CFG, "proposing traffic selectors for %s:",
			 local ? "us" : "other");
		while (e1->enumerate(e1, &ts1))
		{
			/* we make a copy of the TS, this allows us to update dynamic TS' */
			selected = ts1->clone(ts1);
			if (host)
			{
				selected->set_address(selected, host);
			}
			DBG2(DBG_CFG, " %R (derived from %R)", selected, ts1);
			result->insert_last(result, selected);
		}
		e1->destroy(e1);
	}
	else
	{
		DBG2(DBG_CFG, "selecting traffic selectors for %s:",
			 local ? "us" : "other");
		e2 = supplied->create_enumerator(supplied);
		/* iterate over all stored selectors */
		while (e1->enumerate(e1, &ts1))
		{
			/* we make a copy of the TS, as we have to update dynamic TS' */
			ts1 = ts1->clone(ts1);
			if (host)
			{
				ts1->set_address(ts1, host);
			}

			/* iterate over all supplied traffic selectors */
			while (e2->enumerate(e2, &ts2))
			{
				selected = ts1->get_subset(ts1, ts2);
				if (selected)
				{
					DBG2(DBG_CFG, " config: %R, received: %R => match: %R",
						 ts1, ts2, selected);
					result->insert_last(result, selected);
				}
				else
				{
					DBG2(DBG_CFG, " config: %R, received: %R => no match",
						 ts1, ts2);
				}
			}
			e2->destroy(e2);
			e2 = supplied->create_enumerator(supplied);
			ts1->destroy(ts1);
		}
		e1->destroy(e1);
		e2->destroy(e2);
	}

	/* remove any redundant traffic selectors in the list */
	e1 = result->create_enumerator(result);
	e2 = result->create_enumerator(result);
	while (e1->enumerate(e1, &ts1))
	{
		while (e2->enumerate(e2, &ts2))
		{
			if (ts1 != ts2)
			{
				if (ts2->is_contained_in(ts2, ts1))
				{
					result->remove_at(result, e2);
					ts2->destroy(ts2);
					e1->destroy(e1);
					e1 = result->create_enumerator(result);
					break;
				}
				if (ts1->is_contained_in(ts1, ts2))
				{
					result->remove_at(result, e1);
					ts1->destroy(ts1);
					e2->destroy(e2);
					e2 = result->create_enumerator(result);
					break;
				}
			}
		}
	}
	e1->destroy(e1);
	e2->destroy(e2);

	return result;
}

/**
 * Implementation of child_cfg_t.get_updown.
 */
static char* get_updown(private_child_cfg_t *this)
{
	return this->updown;
}

/**
 * Implementation of child_cfg_t.get_hostaccess.
 */
static bool get_hostaccess(private_child_cfg_t *this)
{
	return this->hostaccess;
}

/**
 * Applies jitter to the rekey value. Returns the new rekey value.
 * Note: The distribution of random values is not perfect, but it
 * should get the job done.
 */
static u_int64_t apply_jitter(u_int64_t rekey, u_int64_t jitter)
{
	if (jitter == 0)
	{
		return rekey;
	}
	jitter = (jitter == UINT64_MAX) ? jitter : jitter + 1;
	return rekey - jitter * (random() / (RAND_MAX + 1.0));
}
#define APPLY_JITTER(l) l.rekey = apply_jitter(l.rekey, l.jitter)

/**
 * Implementation of child_cfg_t.get_lifetime.
 */
static lifetime_cfg_t *get_lifetime(private_child_cfg_t *this)
{
	lifetime_cfg_t *lft = malloc_thing(lifetime_cfg_t);
	memcpy(lft, &this->lifetime, sizeof(lifetime_cfg_t));
	APPLY_JITTER(lft->time);
	APPLY_JITTER(lft->bytes);
	APPLY_JITTER(lft->packets);
	return lft;
}

/**
 * Implementation of child_cfg_t.get_mode.
 */
static ipsec_mode_t get_mode(private_child_cfg_t *this)
{
	return this->mode;
}

/**
 * Implementation of child_cfg_t.get_dpd_action.
 */
static action_t get_dpd_action(private_child_cfg_t *this)
{
	return this->dpd_action;
}

/**
 * Implementation of child_cfg_t.get_close_action.
 */
static action_t get_close_action(private_child_cfg_t *this)
{
	return this->close_action;
}

/**
 * Implementation of child_cfg_t.get_dh_group.
 */
static diffie_hellman_group_t get_dh_group(private_child_cfg_t *this)
{
	enumerator_t *enumerator;
	proposal_t *proposal;
	u_int16_t dh_group = MODP_NONE;

	enumerator = this->proposals->create_enumerator(this->proposals);
	while (enumerator->enumerate(enumerator, &proposal))
	{
		if (proposal->get_algorithm(proposal, DIFFIE_HELLMAN_GROUP, &dh_group, NULL))
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	return dh_group;
}

/**
 * Implementation of child_cfg_t.use_ipcomp.
 */
static bool use_ipcomp(private_child_cfg_t *this)
{
	return this->use_ipcomp;
}

/**
 * Implementation of child_cfg_t.set_mipv6_options.
 */
static void set_mipv6_options(private_child_cfg_t *this, bool proxy_mode,
														 bool install_policy)
{
	this->proxy_mode = proxy_mode;
	this->install_policy = install_policy;
}

/**
 * Implementation of child_cfg_t.use_proxy_mode.
 */
static bool use_proxy_mode(private_child_cfg_t *this)
{
	return this->proxy_mode;
}

/**
 * Implementation of child_cfg_t.install_policy.
 */
static bool install_policy(private_child_cfg_t *this)
{
	return this->install_policy;
}

/**
 * Implementation of child_cfg_t.get_ref.
 */
static child_cfg_t* get_ref(private_child_cfg_t *this)
{
	ref_get(&this->refcount);
	return &this->public;
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
child_cfg_t *child_cfg_create(char *name, lifetime_cfg_t *lifetime,
							  char *updown, bool hostaccess,
							  ipsec_mode_t mode, action_t dpd_action,
							  action_t close_action, bool ipcomp)
{
	private_child_cfg_t *this = malloc_thing(private_child_cfg_t);

	this->public.get_name = (char* (*) (child_cfg_t*))get_name;
	this->public.add_traffic_selector = (void (*)(child_cfg_t*,bool,traffic_selector_t*))add_traffic_selector;
	this->public.get_traffic_selectors = (linked_list_t*(*)(child_cfg_t*,bool,linked_list_t*,host_t*))get_traffic_selectors;
	this->public.add_proposal = (void (*) (child_cfg_t*,proposal_t*))add_proposal;
	this->public.get_proposals = (linked_list_t* (*) (child_cfg_t*,bool))get_proposals;
	this->public.select_proposal = (proposal_t* (*) (child_cfg_t*,linked_list_t*,bool))select_proposal;
	this->public.get_updown = (char* (*) (child_cfg_t*))get_updown;
	this->public.get_hostaccess = (bool (*) (child_cfg_t*))get_hostaccess;
	this->public.get_mode = (ipsec_mode_t (*) (child_cfg_t *))get_mode;
	this->public.get_dpd_action = (action_t (*) (child_cfg_t *))get_dpd_action;
	this->public.get_close_action = (action_t (*) (child_cfg_t *))get_close_action;
	this->public.get_lifetime = (lifetime_cfg_t* (*) (child_cfg_t *))get_lifetime;
	this->public.get_dh_group = (diffie_hellman_group_t(*)(child_cfg_t*)) get_dh_group;
	this->public.set_mipv6_options = (void (*) (child_cfg_t*,bool,bool))set_mipv6_options;
	this->public.use_ipcomp = (bool (*) (child_cfg_t *))use_ipcomp;
	this->public.use_proxy_mode = (bool (*) (child_cfg_t *))use_proxy_mode;
	this->public.install_policy = (bool (*) (child_cfg_t *))install_policy;
	this->public.get_ref = (child_cfg_t* (*) (child_cfg_t*))get_ref;
	this->public.destroy = (void (*) (child_cfg_t*))destroy;

	this->name = strdup(name);
	this->updown = updown ? strdup(updown) : NULL;
	this->hostaccess = hostaccess;
	this->mode = mode;
	this->dpd_action = dpd_action;
	this->close_action = close_action;
	this->use_ipcomp = ipcomp;
	this->proxy_mode = FALSE;
	this->install_policy = TRUE;
	this->refcount = 1;
	this->proposals = linked_list_create();
	this->my_ts = linked_list_create();
	this->other_ts = linked_list_create();
	memcpy(&this->lifetime, lifetime, sizeof(lifetime_cfg_t));

	return &this->public;
}

