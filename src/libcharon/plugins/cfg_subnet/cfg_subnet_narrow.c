/*
 * Copyright (C) 2026 Manuel Montesdeoca
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

#include "cfg_subnet_narrow.h"

#include <daemon.h>

typedef struct private_cfg_subnet_narrow_t private_cfg_subnet_narrow_t;

/**
 * Private data of a cfg_subnet_narrow_t object.
 */
struct private_cfg_subnet_narrow_t {

	/**
	 * Public cfg_subnet_narrow_t interface.
	 */
	cfg_subnet_narrow_t public;

	/**
	 * Attribute handler providing the received subnets
	 */
	cfg_subnet_handler_t *handler;
};

/**
 * Narrow the given received subnet with the child configuration and put the
 * result into the given list of traffic selectors
 */
static void narrow_ts(child_cfg_t *cfg, traffic_selector_t *ts,
					  linked_list_t *list)
{
	linked_list_t *received, *selected;

	received = linked_list_create();
	received->insert_last(received, ts);
	selected = cfg->select_traffic_selectors(cfg, FALSE, received, NULL);
	while (selected->remove_first(selected, (void**)&ts) == SUCCESS)
	{
		list->insert_last(list, ts);
	}
	selected->destroy(selected);
	received->destroy(received);
}

/**
 * Narrow TS as initiator to the subnets received via the config payload
 */
static void narrow_initiator(private_cfg_subnet_narrow_t *this,
							 ike_sa_t *ike_sa, child_cfg_t *cfg,
							 linked_list_t *remote)
{
	linked_list_t *orig = NULL;
	traffic_selector_t *current, *ts;
	enumerator_t *enumerator;

	enumerator = this->handler->create_include_enumerator(this->handler,
												ike_sa->get_id(ike_sa));
	while (enumerator->enumerate(enumerator, &current))
	{
		if (!orig)
		{	/* replace the negotiated remote traffic selectors */
			orig = linked_list_create();
			while (remote->remove_first(remote, (void**)&ts) == SUCCESS)
			{
				orig->insert_last(orig, ts);
			}
		}
		narrow_ts(cfg, current, remote);
	}
	enumerator->destroy(enumerator);
	if (!orig)
	{
		return;
	}
	if (remote->get_count(remote))
	{
		DBG1(DBG_CFG, "narrowed CHILD_SA to %d received subnets",
			 remote->get_count(remote));
		DBG2(DBG_CFG, "narrowed remote traffic selectors: %#R", remote);
		while (orig->remove_first(orig, (void**)&ts) == SUCCESS)
		{
			ts->destroy(ts);
		}
	}
	else
	{	/* none of the received subnets matches the config, keep negotiated TS */
		while (orig->remove_first(orig, (void**)&ts) == SUCCESS)
		{
			remote->insert_last(remote, ts);
		}
	}
	orig->destroy(orig);
}

METHOD(listener_t, narrow, bool,
	private_cfg_subnet_narrow_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	narrow_hook_t type, linked_list_t *local, linked_list_t *remote)
{
	if (!ike_sa || ike_sa->get_version(ike_sa) != IKEV2)
	{
		return TRUE;
	}
	switch (type)
	{
		/* the CFG reply is parsed before these hooks are invoked, so any
		 * subnets received for this IKE_SA are available here */
		case NARROW_INITIATOR_POST_NOAUTH:
		case NARROW_INITIATOR_POST_AUTH:
			narrow_initiator(this, ike_sa, child_sa->get_config(child_sa),
							 remote);
			break;
		default:
			break;
	}
	return TRUE;
}

METHOD(listener_t, ike_rekey, bool,
	private_cfg_subnet_narrow_t *this, ike_sa_t *old, ike_sa_t *new)
{
	this->handler->migrate_includes(this->handler,
									old->get_id(old), new->get_id(new));
	return TRUE;
}

METHOD(cfg_subnet_narrow_t, destroy, void,
	private_cfg_subnet_narrow_t *this)
{
	free(this);
}

/*
 * see header file
 */
cfg_subnet_narrow_t *cfg_subnet_narrow_create(cfg_subnet_handler_t *handler)
{
	private_cfg_subnet_narrow_t *this;

	INIT(this,
		.public = {
			.listener = {
				.narrow = _narrow,
				.ike_rekey = _ike_rekey,
			},
			.destroy = _destroy,
		},
		.handler = handler,
	);

	return &this->public;
}
