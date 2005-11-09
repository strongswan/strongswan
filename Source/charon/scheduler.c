/**
 * @file scheduler.c
 *
 * @brief implements the scheduler, looks for jobs in event-queue
 *
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include <stdlib.h>
#include <pthread.h>
#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>

#include "allocator.h"
#include "scheduler.h"
#include "job_queue.h"
#include "globals.h"

/**
 * Private data of a scheduler object
 */
typedef struct private_scheduler_s private_scheduler_t;

struct private_scheduler_s {
	/**
	 * Public part of a scheduler object
	 */
	 scheduler_t public;

	 /**
	  * Assigned thread to the scheduler_t-object
	  */
	 pthread_t assigned_thread;

};

/**
 * Thread function started at creation of the scheduler object
 *
 * @param this assigned scheduler object
 * @return SUCCESS if thread_function ended successfully, FAILED otherwise
 */
static void scheduler_thread_function(private_scheduler_t * this)
{
	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	job_t *current_job;

	for (;;)
	{
		/* get a job, this block until one is available */
		global_event_queue->get(global_event_queue, &current_job);
		/* queue the job in the job queue, workers will eat them */
		global_job_queue->add(global_job_queue, current_job);
	}
}

/**
 * Implementation of scheduler_t's destroy function
 */
static status_t destroy(private_scheduler_t *this)
{
	pthread_cancel(this->assigned_thread);

	pthread_join(this->assigned_thread, NULL);

	allocator_free(this);
	return SUCCESS;
}


scheduler_t * scheduler_create()
{
	private_scheduler_t *this = allocator_alloc_thing(private_scheduler_t);

	this->public.destroy = (status_t(*)(scheduler_t*)) destroy;
	if (pthread_create(&(this->assigned_thread), NULL, (void*(*)(void*))scheduler_thread_function, this) != 0)
	{
		/* thread could not be created  */
		allocator_free(this);
		return NULL;
	}

	return &(this->public);
}
