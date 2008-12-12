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

#include "load_tester_listener.h"

#include <signal.h>

#include <daemon.h>
#include <processing/jobs/delete_ike_sa_job.h>

typedef struct private_load_tester_listener_t private_load_tester_listener_t;

/**
 * Private data of an load_tester_listener_t object
 */
struct private_load_tester_listener_t {
	/**
	 * Public part
	 */
	load_tester_listener_t public;
	
	/**
	 * Delete IKE_SA after it has been established
	 */
	bool delete_after_established;

	/**
	 * Number of established SAs
	 */
	u_int established;
	
	/**
	 * Shutdown the daemon if we have established this SA count
	 */
	u_int shutdown_on;
};

/**
 * Implementation of listener_t.ike_state_change
 */
static bool ike_state_change(private_load_tester_listener_t *this,
							 ike_sa_t *ike_sa, ike_sa_state_t state)
{
	if (state == IKE_ESTABLISHED)
	{
		ike_sa_id_t *id = ike_sa->get_id(ike_sa);
	
		if (this->delete_after_established)
		{
			charon->processor->queue_job(charon->processor,
									(job_t*)delete_ike_sa_job_create(id, TRUE));
		}
		
		if (id->is_initiator(id))
		{
			if (this->shutdown_on == ++this->established)
			{
				DBG1(DBG_CFG, "load-test complete, raising SIGTERM");
				pthread_kill(charon->main_thread_id, SIGTERM);
			}
		}
	}
	return TRUE;
}

/**
 * Implementation of load_tester_listener_t.destroy
 */
static void destroy(private_load_tester_listener_t *this)
{
	free(this);
}

load_tester_listener_t *load_tester_listener_create(u_int shutdown_on)
{
	private_load_tester_listener_t *this = malloc_thing(private_load_tester_listener_t);
	
	memset(&this->public.listener, 0, sizeof(listener_t));
	this->public.listener.ike_state_change = (void*)ike_state_change;
	this->public.destroy = (void(*) (load_tester_listener_t*))destroy;
	
	this->delete_after_established = lib->settings->get_bool(lib->settings,
				"charon.plugins.load_tester.delete_after_established", FALSE);
	
	this->shutdown_on = shutdown_on;
	this->established = 0;
	
	return &this->public;
}

