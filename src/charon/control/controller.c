/**
 * @file controller.c
 * 
 * @brief Implementation of controller_t.
 * 
 */

/*
 * Copyright (C) 2007 Martin Willi
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

#include "controller.h"

#include <daemon.h>
#include <library.h>
#include <processing/job_queue.h>
#include <processing/jobs/initiate_job.h>


typedef struct private_controller_t private_controller_t;

/**
 * Private data of an stroke_t object.
 */
struct private_controller_t {

	/**
	 * Public part of stroke_t object.
	 */
	controller_t public;
};
	
/**
 * Implementation of controller_t.initiate.
 */
static status_t initiate(private_controller_t *this,
						 peer_cfg_t *peer_cfg, child_cfg_t *child_cfg,
						 bool(*cb)(void*,signal_t,level_t,ike_sa_t*,char*,va_list),
						 void *param)
{
	ike_sa_t *ours = NULL;
	job_t *job;
	status_t retval;
	
	charon->bus->set_listen_state(charon->bus, TRUE);
	
	job = (job_t*)initiate_job_create(peer_cfg, child_cfg);
	charon->job_queue->add(charon->job_queue, job);
	
	while (TRUE)
	{
		level_t level;
		signal_t signal;
		int thread;
		ike_sa_t *ike_sa;
		char* format;
		va_list args;
		
		signal = charon->bus->listen(charon->bus, &level, &thread, 
									 &ike_sa, &format, &args);
		
		if (ike_sa == ours || ours == NULL)
		{
			if (!cb(param, signal, level, ike_sa, format, args))
			{
				charon->bus->set_listen_state(charon->bus, FALSE);
				return NEED_MORE;
			}
		}
		
		switch (signal)
		{
			case CHILD_UP_SUCCESS:
				if (ike_sa == ours)
				{
					retval = SUCCESS;
					break;
				}
				continue;
			case CHILD_UP_FAILED:
			case IKE_UP_FAILED:
				if (ike_sa == ours)
				{
					retval = FAILED;
					break;
				}
				continue;
			case CHILD_UP_START:
			case IKE_UP_START:
				if (ours == NULL)
				{
					ours = ike_sa;
				}
				continue;
			default:
				continue;
		}
		break;
	}
	charon->bus->set_listen_state(charon->bus, FALSE);
	return retval;
}

/**
 * Implementation of stroke_t.destroy.
 */
static void destroy(private_controller_t *this)
{
	free(this);
}

/*
 * Described in header-file
 */
controller_t *controller_create(void)
{
	private_controller_t *this = malloc_thing(private_controller_t);
	
	this->public.initiate = (status_t(*)(controller_t*,peer_cfg_t*,child_cfg_t*,bool(*)(void*,signal_t,level_t,ike_sa_t*,char*,va_list),void*))initiate;
	this->public.destroy = (void (*)(controller_t*))destroy;
	
	return &this->public;
}
