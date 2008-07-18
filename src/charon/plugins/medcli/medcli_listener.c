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
static bool signal_(private_medcli_listener_t *this, signal_t signal,
					level_t level, int thread, ike_sa_t* ike_sa, void *data,
					char *format, va_list args)
{
	mediated_state_t state;
	
	if (!ike_sa)
	{
		return TRUE;
	}

	switch (signal)
	{
		case IKE_UP_START:
			state = STATE_CONNECTING;
			break;
		case IKE_UP_FAILED:
		case IKE_DOWN_SUCCESS:
		case IKE_DOWN_FAILED:
			state = STATE_DOWN;
			break;
		case IKE_UP_SUCCESS:
			state = STATE_UP;
			break;
		default:
			return TRUE;
	}
	this->db->execute(this->db, NULL,
					  "UPDATE Connection SET Status = ? WHERE Alias = ?",
					  DB_UINT, state, DB_TEXT, ike_sa->get_name(ike_sa));
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

	this->public.listener.signal = (bool(*)(bus_listener_t*,signal_t,level_t,int,ike_sa_t*,void*,char*,va_list))signal_;
	this->public.destroy = (void (*)(medcli_listener_t*))destroy;
	
	this->db = db;
	db->execute(db, NULL, "UPDATE Connection SET Status = ?",
				DB_UINT, STATE_DOWN);
	
	return &this->public;
}

