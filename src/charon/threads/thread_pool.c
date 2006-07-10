/**
 * @file thread_pool.c
 *
 * @brief Implementation of thread_pool_t.
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
#include <string.h>
#include <errno.h>

#include "thread_pool.h"
 
#include <daemon.h>
#include <queues/job_queue.h>
#include <utils/logger.h>


typedef struct private_thread_pool_t private_thread_pool_t;

/**
 * @brief Private data of thread_pool_t class.
 */
struct private_thread_pool_t {
	/**
	 * Public thread_pool_t interface.
	 */
	thread_pool_t public;

	/**
	 * Number of running threads.
	 */
	size_t pool_size;
	
	/**
	 * Array of thread ids.
	 */
	pthread_t *threads;
	
	/**
	 * Logger of the thread pool.
	 */
	logger_t *logger;
} ;

/**
 * Implementation of private_thread_pool_t.process_jobs.
 */
static void process_jobs(private_thread_pool_t *this)
{
	job_t *job;
	status_t status;
	
	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	
	this->logger->log(this->logger, CONTROL,
					  "worker thread running,    thread_ID: %06u",
					  (int)pthread_self());
	
	while (TRUE)
	{
		job = charon->job_queue->get(charon->job_queue);
		
		status = job->execute(job);
		
		if (status == DESTROY_ME)
		{
			job->destroy(job);
		}
	}
}

/**
 * Implementation of thread_pool_t.get_pool_size.
 */
static size_t get_pool_size(private_thread_pool_t *this)
{
	return this->pool_size;
}

/**
 * Implementation of thread_pool_t.destroy.
 */
static void destroy(private_thread_pool_t *this)
{	
	int current;
	/* flag thread for termination */
	for (current = 0; current < this->pool_size; current++) {
		this->logger->log(this->logger, CONTROL, 
						  "cancelling worker thread #%d", current+1);
		pthread_cancel(this->threads[current]);
	}
	
	/* wait for all threads */
	for (current = 0; current < this->pool_size; current++) {
		if (pthread_join(this->threads[current], NULL) == 0)
		{
			this->logger->log(this->logger, CONTROL, 
							  "worker thread #%d terminated", current+1);
		}
		else
		{
			this->logger->log(this->logger, ERROR, 
							  "could not terminate worker thread #%d", current+1);
		}
	}
	
	/* free mem */
	free(this->threads);
	free(this);
}

/*
 * Described in header.
 */
thread_pool_t *thread_pool_create(size_t pool_size)
{
	int current;
	private_thread_pool_t *this = malloc_thing(private_thread_pool_t);
	
	/* fill in public fields */
	this->public.destroy = (void(*)(thread_pool_t*))destroy;
	this->public.get_pool_size = (size_t(*)(thread_pool_t*))get_pool_size;
	
	/* initialize member */
	this->pool_size = pool_size;
	this->threads = malloc(sizeof(pthread_t) * pool_size);
	this->logger = logger_manager->get_logger(logger_manager, THREAD_POOL);
	
	/* try to create as many threads as possible, up to pool_size */
	for (current = 0; current < pool_size; current++) 
	{
		if (pthread_create(&(this->threads[current]), NULL, 
						   (void*(*)(void*))process_jobs, this) == 0)
		{
			this->logger->log(this->logger, CONTROL, 
							  "created worker thread #%d", current+1);
		}
		else
		{
			/* creation failed, is it the first one? */	
			if (current == 0) 
			{
				this->logger->log(this->logger, ERROR, "Could not create any thread");
				free(this->threads);
				free(this);
				return NULL;
			}
			/* not all threads could be created, but at least one :-/ */
			this->logger->log(this->logger, ERROR,
							  "Could only create %d from requested %d threads!",
							  current, pool_size);
				
			this->pool_size = current;
			return (thread_pool_t*)this;
		}
	}
	return (thread_pool_t*)this;
}
