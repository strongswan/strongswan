/*
 * Copyright (C) 2015 Martin Willi
 * Copyright (C) 2015 revosec AG
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

#include "narrowid_narrow.h"

#include <daemon.h>

typedef struct private_narrowid_narrow_t private_narrowid_narrow_t;

/**
 * Private data of an narrowid_narrow_t object.
 */
struct private_narrowid_narrow_t {

	/**
	 * Public narrowid_narrow_t interface.
	 */
	narrowid_narrow_t public;

	/**
	 * Space separated list of configs we do narrowing for
	 */
	char *configs;
};

/**
 * Narrow list of traffic selectors to authenticated remote identities
 */
static void narrow_to_ids(private_narrowid_narrow_t *this,
						  ike_sa_t *ike_sa, linked_list_t *list)
{
	traffic_selector_t *current, *ts, *subset;
	enumerator_t *enumerator;
	identification_t *id;
	linked_list_t *orig;
	auth_cfg_t *auth;
	ts_type_t type;

	orig = linked_list_create();

	while (list->remove_first(list, (void**)&current) == SUCCESS)
	{
		orig->insert_last(orig, current);
	}

	while (orig->remove_first(orig, (void**)&current) == SUCCESS)
	{
		enumerator = ike_sa->create_auth_cfg_enumerator(ike_sa, FALSE);
		while (enumerator->enumerate(enumerator, &auth))
		{
			id = auth->get(auth, AUTH_RULE_IDENTITY);
			if (id)
			{
				switch (id->get_type(id))
				{
					case ID_IPV4_ADDR:
						type = TS_IPV4_ADDR_RANGE;
						break;
					case ID_IPV6_ADDR:
						type = TS_IPV6_ADDR_RANGE;
						break;
					default:
						continue;
				}
				ts = traffic_selector_create_from_bytes(0, type,
						id->get_encoding(id), 0, id->get_encoding(id), 65535);
				if (ts)
				{
					subset = current->get_subset(current, ts);
					if (subset)
					{
						list->insert_last(list, subset);
					}
					ts->destroy(ts);
				}
			}
		}
		enumerator->destroy(enumerator);

		current->destroy(current);
	}

	orig->destroy(orig);

	if (list->get_count(list))
	{
		DBG1(DBG_CFG, "narrowed selectors to peer identities: %#R", list);
	}
	else
	{
		DBG1(DBG_CFG, "narrowing selectors to peer identites gives empty set");
	}
}

/**
 * Check if we should do narrowing for the given CHILD_SA config
 */
static bool do_narrowing_for(private_narrowid_narrow_t *this, char *config)
{
	enumerator_t *enumerator;
	char *token;
	bool found = FALSE;

	if (!this->configs)
	{	/* none by default */
		return FALSE;
	}

	enumerator = enumerator_create_token(this->configs, " ", "");
	while (enumerator->enumerate(enumerator, &token))
	{
		if (streq(token, config))
		{
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	return found;
}

METHOD(listener_t, narrow, bool,
	private_narrowid_narrow_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	narrow_hook_t type, linked_list_t *local, linked_list_t *remote)
{
	switch (type)
	{
		case NARROW_RESPONDER:
		case NARROW_INITIATOR_POST_AUTH:
		case NARROW_INITIATOR_POST_NOAUTH:
			if (do_narrowing_for(this, child_sa->get_name(child_sa)))
			{
				narrow_to_ids(this, ike_sa, remote);
			}
			break;
		default:
			break;
	}
	return TRUE;
}

METHOD(narrowid_narrow_t, destroy, void,
	private_narrowid_narrow_t *this)
{
	free(this);
}

/**
 * See header
 */
narrowid_narrow_t *narrowid_narrow_create()
{
	private_narrowid_narrow_t *this;

	INIT(this,
		.public = {
			.listener = {
				.narrow = _narrow,
			},
			.destroy = _destroy,
		},
		.configs = lib->settings->get_str(lib->settings,
								"%s.plugins.narrowid.configs", NULL, lib->ns),
	);

	return &this->public;
}
