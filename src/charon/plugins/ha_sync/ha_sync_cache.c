/*
 * Copyright (C) 2008 Martin Willi
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
 *
 * $Id$
 */

#include "ha_sync_cache.h"

#include <utils/linked_list.h>

typedef struct private_ha_sync_cache_t private_ha_sync_cache_t;

/**
 * Private data of an ha_sync_cache_t object.
 */
struct private_ha_sync_cache_t {

	/**
	 * Public ha_sync_cache_t interface.
	 */
	ha_sync_cache_t public;

	/**
	 * Linked list of IKE_SAs, ike_sa_t
	 */
	linked_list_t *list;
};

/**
 * Implementation of ha_sync_cache_t.get_ike_sa
 */
static ike_sa_t* get_ike_sa(private_ha_sync_cache_t *this, ike_sa_id_t *id)
{
	enumerator_t *enumerator;
	ike_sa_t *current, *found = NULL;

	enumerator = this->list->create_enumerator(this->list);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (id->equals(id, current->get_id(current)))
		{
			found = current;
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (!found)
	{
		found = ike_sa_create(id);
		this->list->insert_first(this->list, found);
	}
	return found;
}

/**
 * Implementation of ha_sync_cache_t.delete_ike_sa
 */
static void delete_ike_sa(private_ha_sync_cache_t *this, ike_sa_id_t *id)
{
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;

	enumerator = this->list->create_enumerator(this->list);
	while (enumerator->enumerate(enumerator, &ike_sa))
	{
		if (id->equals(id, ike_sa->get_id(ike_sa)))
		{
			this->list->remove_at(this->list, enumerator);
			ike_sa->destroy(ike_sa);
			break;
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Implementation of ha_sync_cache_t.activate_segment
 */
static void activate_segment(private_ha_sync_cache_t *this, u_int segment)
{
	ike_sa_t *ike_sa;

	/* TODO: activate only segment, not all */
	while (this->list->remove_last(this->list, (void**)&ike_sa) == SUCCESS)
	{
		/* TODO: fix checkin of inexisting IKE_SA in manager */
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	}
}

/**
 * Implementation of ha_sync_cache_t.destroy.
 */
static void destroy(private_ha_sync_cache_t *this)
{
	this->list->destroy_offset(this->list, offsetof(ike_sa_t, destroy));
	free(this);
}

/**
 * See header
 */
ha_sync_cache_t *ha_sync_cache_create()
{
	private_ha_sync_cache_t *this = malloc_thing(private_ha_sync_cache_t);

	this->public.get_ike_sa = (ike_sa_t*(*)(ha_sync_cache_t*, ike_sa_id_t *id))get_ike_sa;
	this->public.delete_ike_sa = (void(*)(ha_sync_cache_t*, ike_sa_id_t *id))delete_ike_sa;
	this->public.activate_segment = (void(*)(ha_sync_cache_t*, u_int segment))activate_segment;
	this->public.destroy = (void(*)(ha_sync_cache_t*))destroy;

	this->list = linked_list_create();

	return &this->public;
}

