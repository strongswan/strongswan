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

#include "scheduler.h"

#include <globals.h>
#include <definitions.h>
#include <utils/allocator.h>
#include <utils/logger_manager.h>
#include <queues/job_queue.h>

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
	  * Assigned thread to the scheduler_t object
	  */
	 pthread_t assigned_thread;
	 
	 /** 
	  * logger for this scheduler
	  */
	 logger_t *logger;

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
		this->logger->log(this->logger, CONTROL|MORE, "waiting for next event...");
		/* get a job, this block until one is available */
		global_event_queue->get(global_event_queue, &current_job);
		/* queue the job in the job queue, workers will eat them */
		global_job_queue->add(global_job_queue, current_job);
		this->logger->log(this->logger, CONTROL, "got event, added job %s to job-queue.", mapping_find(job_type_m, current_job->get_type(current_job)));
	}
}

/**
 * Implementation of scheduler_t's destroy function
 */
static status_t destroy(private_scheduler_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to terminate scheduler thread");
	pthread_cancel(this->assigned_thread);

	pthread_join(this->assigned_thread, NULL);
	this->logger->log(this->logger, CONTROL | MORE, "Scheduler thread terminated");	
	
	global_logger_manager->destroy_logger(global_logger_manager, this->logger);

	allocator_free(this);
	return SUCCESS;
}


scheduler_t * scheduler_create()
{
	private_scheduler_t *this = allocator_alloc_thing(private_scheduler_t);

	this->public.destroy = (status_t(*)(scheduler_t*)) destroy;
	
	this->logger = global_logger_manager->create_logger(global_logger_manager, SCHEDULER, NULL);
	if (this->logger == NULL)
	{
		allocator_free(this);
		return NULL;	
	}
	
	if (pthread_create(&(this->assigned_thread), NULL, (void*(*)(void*))scheduler_thread_function, this) != 0)
	{
		/* thread could not be created  */
		global_logger_manager->destroy_logger(global_logger_manager, this->logger);
		allocator_free(this);
		return NULL;
	}

	return &(this->public);
}
