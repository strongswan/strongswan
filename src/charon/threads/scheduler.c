/**
 * @file scheduler.c
 *
 * @brief Implementation of scheduler_t.
 *
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
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

#include <stdlib.h>
#include <pthread.h>

#include "scheduler.h"

#include <daemon.h>
#include <definitions.h>
#include <utils/logger_manager.h>
#include <queues/job_queue.h>


typedef struct private_scheduler_t private_scheduler_t;

/**
 * Private data of a scheduler_t object.
 */
struct private_scheduler_t {
	/**
	 * Public part of a scheduler_t object.
	 */
	 scheduler_t public;

	/**
	 * Assigned thread.
	 */
	pthread_t assigned_thread;
	
	/** 
	 * A logger.
	 */
	logger_t *logger;
};

/**
 * Implementation of private_scheduler_t.get_events.
 */
static void get_events(private_scheduler_t * this)
{
	job_t *current_job;
	
	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	
	this->logger->log(this->logger, CONTROL, "scheduler thread running, thread_ID: %06u", (int)pthread_self());

	while (TRUE)
	{
		this->logger->log(this->logger, CONTROL|LEVEL2, "waiting for next event...");
		/* get a job, this block until one is available */
		current_job = charon->event_queue->get(charon->event_queue);
		/* queue the job in the job queue, workers will eat them */
		this->logger->log(this->logger, CONTROL | LEVEL1, "got event, adding job %s to job-queue.", 
						  mapping_find(job_type_m, current_job->get_type(current_job)));
		charon->job_queue->add(charon->job_queue, current_job);
	}
}

/**
 * Implementation of scheduler_t.destroy.
 */
static void destroy(private_scheduler_t *this)
{
	this->logger->log(this->logger, CONTROL | LEVEL1, "going to terminate scheduler thread");
	pthread_cancel(this->assigned_thread);

	pthread_join(this->assigned_thread, NULL);
	this->logger->log(this->logger, CONTROL | LEVEL1, "scheduler thread terminated");

	free(this);
}

/*
 * Described in header.
 */
scheduler_t * scheduler_create()
{
	private_scheduler_t *this = malloc_thing(private_scheduler_t);

	this->public.destroy = (void(*)(scheduler_t*)) destroy;
	
	this->logger = logger_manager->get_logger(logger_manager, SCHEDULER);
	
	if (pthread_create(&(this->assigned_thread), NULL, (void*(*)(void*))get_events, this) != 0)
	{
		/* thread could not be created  */
		this->logger->log(this->logger, ERROR, "scheduler thread could not be created!");
		free(this);
		charon->kill(charon, "unable to create scheduler thread");
	}

	return &(this->public);
}
