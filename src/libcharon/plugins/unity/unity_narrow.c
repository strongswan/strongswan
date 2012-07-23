/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "unity_narrow.h"

#include <daemon.h>

typedef struct private_unity_narrow_t private_unity_narrow_t;

/**
 * Private data of an unity_narrow_t object.
 */
struct private_unity_narrow_t {

	/**
	 * Public unity_narrow_t interface.
	 */
	unity_narrow_t public;

	/**
	 * Unity attribute handler
	 */
	unity_handler_t *handler;
};

METHOD(listener_t, narrow, bool,
	private_unity_narrow_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	narrow_hook_t type, linked_list_t *local, linked_list_t *remote)
{
	traffic_selector_t *current, *orig = NULL;
	enumerator_t *enumerator;

	if (type == NARROW_INITIATOR_POST_AUTH &&
		remote->get_count(remote) == 1)
	{
		enumerator = this->handler->create_include_enumerator(this->handler,
												ike_sa->get_unique_id(ike_sa));
		while (enumerator->enumerate(enumerator, &current))
		{
			if (orig == NULL)
			{	/* got one, replace original TS */
				remote->remove_first(remote, (void**)&orig);
			}
			remote->insert_last(remote, orig->get_subset(orig, current));
		}
		enumerator->destroy(enumerator);
		if (orig)
		{
			DBG1(DBG_CFG, "narrowed CHILD_SA to %N %#R",
				 configuration_attribute_type_names,
				 UNITY_SPLIT_INCLUDE, remote);
			orig->destroy(orig);
		}
	}
	return TRUE;
}

METHOD(unity_narrow_t, destroy, void,
	private_unity_narrow_t *this)
{
	free(this);
}

/**
 * See header
 */
unity_narrow_t *unity_narrow_create(unity_handler_t *handler)
{
	private_unity_narrow_t *this;

	INIT(this,
		.public = {
			.listener = {
				.narrow = _narrow,
			},
			.destroy = _destroy,
		},
		.handler = handler,
	);

	return &this->public;
}
