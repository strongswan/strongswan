/**
 * @file thread_pool.c
 * 
 * @brief Thread pool with some threads processing the job_queue.
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
#include <string.h>
#include <errno.h>
 
#include "allocator.h"
#include "logger.h"
#include "thread_pool.h"
#include "job_queue.h"
#include "globals.h"

/**
 * @brief structure with private members for thread_pool_t
 */
typedef struct private_thread_pool_s private_thread_pool_t;

struct private_thread_pool_s {
	/**
	 * inclusion of public members
	 */
	thread_pool_t public;
	/**
	 * @brief Processing function of a worker thread
	 * 
	 * @param this	private_thread_pool_t-Object
	 */
	void (*function) (private_thread_pool_t *this);
	/**
	 * number of running threads
	 */
	 size_t pool_size;
	/**
	 * array of thread ids
	 */
	pthread_t *threads;
	/**
	 * logger of the threadpool
	 */
	logger_t *logger;
} ;



/**
 * implements private_thread_pool_t.function
 */
static void job_processing(private_thread_pool_t *this)
{
	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	
	this->logger->log(this->logger, CONTROL_MORE, "thread %u started working", pthread_self());

	for (;;) {
		job_t *job;

		global_job_queue->get(global_job_queue, &job);
		this->logger->log(this->logger, CONTROL_MORE, "thread %u got a job", pthread_self());
		
		/* process them here */
		
		job->destroy(job);
	}

}

/**
 * implementation of thread_pool_t.get_pool_size
 */
static size_t get_pool_size(private_thread_pool_t *this)
{
	return this->pool_size;
}

/**
 * Implementation of thread_pool_t.destroy
 */
static status_t destroy(private_thread_pool_t *this)
{	
	int current;
	/* flag thread for termination */
	for (current = 0; current < this->pool_size; current++) {
		this->logger->log(this->logger, CONTROL, "cancelling thread %u", this->threads[current]);
		pthread_cancel(this->threads[current]);
	}
	
	/* wait for all threads */
	for (current = 0; current < this->pool_size; current++) {
		pthread_join(this->threads[current], NULL);
		this->logger->log(this->logger, CONTROL, "thread %u terminated", this->threads[current]);
	}	

	/* free mem */
	this->logger->destroy(this->logger);
	allocator_free(this->threads);
	allocator_free(this);
	return SUCCESS;
}

#include <stdio.h>

/*
 * see header
 */
thread_pool_t *thread_pool_create(size_t pool_size)
{
	int current;
	
	private_thread_pool_t *this = allocator_alloc_thing(private_thread_pool_t);
	
	/* fill in public fields */
	this->public.destroy = (status_t(*)(thread_pool_t*))destroy;
	this->public.get_pool_size = (size_t(*)(thread_pool_t*))get_pool_size;
	
	this->function = job_processing;
	this->pool_size = pool_size;
	
	this->threads = allocator_alloc(sizeof(pthread_t) * pool_size);
	if (this->threads == NULL)
	{
		allocator_free(this);
		return NULL;
	}	
	this->logger = logger_create("thread_pool", ALL);
	if (this->threads == NULL)
	{
		allocator_free(this);
		allocator_free(this->threads);
		return NULL;
	}	
	
	/* try to create as many threads as possible, up tu pool_size */
	for (current = 0; current < pool_size; current++) 
	{
		if (pthread_create(&(this->threads[current]), NULL, (void*(*)(void*))this->function, this) == 0) 
		{
			this->logger->log(this->logger, CONTROL, "thread %u created", this->threads[current]);
		}
		else 
		{
			/* creation failed, is it the first one? */	
			if (current == 0) 
			{
				this->logger->log(this->logger, CONTROL, "could not create any thread: %s\n", strerror(errno));
				allocator_free(this->threads);
				allocator_free(this->logger);
				allocator_free(this);
				return NULL;
			}
			/* not all threads could be created, but at least one :-/ */
			this->logger->log(this->logger, CONTROL, "could only create %d from requested %d threads: %s\n", current, pool_size, strerror(errno));
				
			this->pool_size = current;
			return (thread_pool_t*)this;
		}
	}	
	return (thread_pool_t*)this;
}
