/**
 * @file thread_pool.c
 * 
 * @brief Thread-pool with some threads processing the job_queue
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
 * structure with private members for thread_pool
 */
typedef struct {
	/**
	 * inclusion of public members
	 */
	thread_pool_t public;
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
} private_thread_pool_t;


static void job_processing(private_thread_pool_t *this)
{
	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	for (;;) {
		job_t *job;

		global_job_queue->get(global_job_queue, &job);
		
		/* process them here */
		
		job->destroy(job);
	}

}

/**
 * Implementation of thread_pool_t.get_pool_size
 */
static status_t get_pool_size(private_thread_pool_t *this, size_t *size)
{
	*size = this->pool_size;
	return SUCCESS;
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
	allocator_free(this->threads);
	allocator_free(this);
	return SUCCESS;
}

/**
 * Implementation of default constructor for thread_pool_t
 */
thread_pool_t *thread_pool_create(size_t pool_size)
{
	int current;
	
	private_thread_pool_t *this = allocator_alloc_thing(private_thread_pool_t);
	
	/* fill in public fields */
	this->public.destroy = (status_t(*)(thread_pool_t*))destroy;
	this->public.get_pool_size = (status_t(*)(thread_pool_t*, size_t*))get_pool_size;
	
	this->pool_size = pool_size;
	this->threads = allocator_alloc(sizeof(pthread_t) * pool_size);
	this->logger = logger_create("thread_pool", 0);
	
	/* try to create as many threads as possible, up tu pool_size */
	for (current = 0; current < pool_size; current++) {
		if (pthread_create(&(this->threads[current]), NULL, (void*(*)(void*))job_processing, this)) 
		{
			/* did we get any? */	
			if (current == 0) 
			{
				this->logger->log(this->logger, CONTROL, "could not create any thread: %s\n", strerror(errno));
				allocator_free(this->threads);
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
