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
 */

#include "medcli_listener.h"

#include <daemon.h>
#include <library.h>

typedef struct private_medcli_listener_t private_medcli_listener_t;
typedef enum mediated_state_t mediated_state_t;

/**
 * state of a mediated connection
 */
enum mediated_state_t {
	STATE_DOWN = 1,
	STATE_CONNECTING = 2,
	STATE_UP = 3,
};

/**
 * Private data of an medcli_listener_t object
 */
struct private_medcli_listener_t {

	/**
	 * Public part
	 */
	medcli_listener_t public;

	/**
	 * underlying database handle
	 */
	database_t *db;
};

/**
 * Implementation of bus_listener_t.signal.
 */
static void set_state(private_medcli_listener_t *this, char *alias,
					  mediated_state_t state)
{
	this->db->execute(this->db, NULL,
					  "UPDATE Connection SET Status = ? WHERE Alias = ?",
					  DB_UINT, state, DB_TEXT, alias);
}
/**
 * Implementation of listener_t.ike_state_change
 */
static bool ike_state_change(private_medcli_listener_t *this,
							 ike_sa_t *ike_sa, ike_sa_state_t state)
{
	if (ike_sa)
	{
		switch (state)
		{
			case IKE_CONNECTING:
				set_state(this, ike_sa->get_name(ike_sa), STATE_CONNECTING);
				break;
			case IKE_DESTROYING:
				set_state(this, ike_sa->get_name(ike_sa), STATE_DOWN);
			default:
				break;
		}
	}
	return TRUE;
}

/**
 * Implementation of listener_t.child_state_change
 */
static bool child_state_change(private_medcli_listener_t *this,
				ike_sa_t *ike_sa, child_sa_t *child_sa, child_sa_state_t state)
{
	if (ike_sa && child_sa)
	{
		switch (state)
		{
			case CHILD_INSTALLED:
				set_state(this, child_sa->get_name(child_sa), STATE_UP);
				break;
			case CHILD_DESTROYING:
				set_state(this, child_sa->get_name(child_sa), STATE_DOWN);
				break;
			default:
				break;
		}
	}
	return TRUE;
}

/**
 * Implementation of backend_t.destroy.
 */
static void destroy(private_medcli_listener_t *this)
{
	this->db->execute(this->db, NULL, "UPDATE Connection SET Status = ?",
					  DB_UINT, STATE_DOWN);
	free(this);
}

/**
 * Described in header.
 */
medcli_listener_t *medcli_listener_create(database_t *db)
{
	private_medcli_listener_t *this = malloc_thing(private_medcli_listener_t);

	memset(&this->public.listener, 0, sizeof(listener_t));

	this->public.listener.ike_state_change = (void*)ike_state_change;
	this->public.listener.child_state_change = (void*)child_state_change;
	this->public.destroy = (void (*)(medcli_listener_t*))destroy;

	this->db = db;
	db->execute(db, NULL, "UPDATE Connection SET Status = ?",
				DB_UINT, STATE_DOWN);

	return &this->public;
}

