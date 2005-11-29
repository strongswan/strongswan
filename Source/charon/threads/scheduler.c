/**
 * @file scheduler.c
 *
 * @brief Implementation of scheduler_t.
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
#include <unistd.h>

#include "scheduler.h"

#include <daemon.h>
#include <definitions.h>
#include <utils/allocator.h>
#include <utils/logger_manager.h>
#include <queues/job_queue.h>

/**
 * Private data of a scheduler object
 */
typedef struct private_scheduler_t private_scheduler_t;

struct private_scheduler_t {
	/**
	 * Public part of a scheduler object
	 */
	 scheduler_t public;
	 
	/**
	 * @brief Get events from the event queue and add them to to job queue.
	 *
	 * Thread function started at creation of the scheduler object.
	 *
	 * @param this 		assigned scheduler object
	 */
	void (*get_events) (private_scheduler_t *this);

	/**
	 * Assigned thread to the scheduler_t object
	 */
	pthread_t assigned_thread;
	
	/** 
	 * logger for this scheduler
	 */
	logger_t *logger;
};

/**
 * implements private_scheduler_t.get_events
 */
static void get_events(private_scheduler_t * this)
{
	job_t *current_job;
	
	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	
	this->logger->log(this->logger, CONTROL, "scheduler thread running, pid %d", getpid());

	for (;;)
	{
		this->logger->log(this->logger, CONTROL|MORE, "waiting for next event...");
		/* get a job, this block until one is available */
		current_job = charon->event_queue->get(charon->event_queue);
		/* queue the job in the job queue, workers will eat them */
		charon->job_queue->add(charon->job_queue, current_job);
		this->logger->log(this->logger, CONTROL, "got event, added job %s to job-queue.", 
						  mapping_find(job_type_m, current_job->get_type(current_job)));
	}
}

/**
 * Implementation of scheduler_t's destroy function
 */
static void destroy(private_scheduler_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to terminate scheduler thread");
	pthread_cancel(this->assigned_thread);

	pthread_join(this->assigned_thread, NULL);
	this->logger->log(this->logger, CONTROL | MORE, "Scheduler thread terminated");	
	
	charon->logger_manager->destroy_logger(charon->logger_manager, this->logger);

	allocator_free(this);
}


scheduler_t * scheduler_create()
{
	private_scheduler_t *this = allocator_alloc_thing(private_scheduler_t);

	this->public.destroy = (void(*)(scheduler_t*)) destroy;
	this->get_events = get_events;
	
	this->logger = charon->logger_manager->create_logger(charon->logger_manager, SCHEDULER, NULL);
	
	if (pthread_create(&(this->assigned_thread), NULL, (void*(*)(void*))this->get_events, this) != 0)
	{
		/* thread could not be created  */
		this->logger->log(this->logger, ERROR, "Scheduler thread could not be created!");
		charon->logger_manager->destroy_logger(charon->logger_manager, this->logger);
		allocator_free(this);
		return NULL;
	}

	return &(this->public);
}
