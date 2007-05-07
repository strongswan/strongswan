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
#include <processing/job_queue.h>


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
	u_int pool_size;
	
	/**
	 * Number of threads waiting for work
	 */
	u_int idle_threads;
	
	/**
	 * Array of thread ids.
	 */
	pthread_t *threads;
};

/**
 * Implementation of private_thread_pool_t.process_jobs.
 */
static void process_jobs(private_thread_pool_t *this)
{
	job_t *job;
	status_t status;
	
	/* cancellation disabled by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	
	DBG1(DBG_JOB, "worker thread running, thread_ID: %06u",
		 (int)pthread_self());
	
	/* drop threads capabilities, except CAP_NET_ADMIN */
	charon->drop_capabilities(charon, TRUE, TRUE, FALSE);
	
	while (TRUE)
	{
		/* TODO: should be atomic, but is not mission critical */
		this->idle_threads++;
		job = charon->job_queue->get(charon->job_queue);
		this->idle_threads--;
		
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
static u_int get_pool_size(private_thread_pool_t *this)
{
	return this->pool_size;
}

/**
 * Implementation of thread_pool_t.get_idle_threads.
 */
static u_int get_idle_threads(private_thread_pool_t *this)
{
	return this->idle_threads;
}

/**
 * Implementation of thread_pool_t.destroy.
 */
static void destroy(private_thread_pool_t *this)
{	
	int current;
	/* flag thread for termination */
	for (current = 0; current < this->pool_size; current++)
	{
		DBG1(DBG_JOB, "cancelling worker thread #%d", current+1);
		pthread_cancel(this->threads[current]);
	}
	
	/* wait for all threads */
	for (current = 0; current < this->pool_size; current++) {
		if (pthread_join(this->threads[current], NULL) == 0)
		{
			DBG1(DBG_JOB, "worker thread #%d terminated", current+1);
		}
		else
		{
			DBG1(DBG_JOB, "could not terminate worker thread #%d", current+1);
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
	this->public.get_pool_size = (u_int(*)(thread_pool_t*))get_pool_size;
	this->public.get_idle_threads = (u_int(*)(thread_pool_t*))get_idle_threads;
	
	/* initialize member */
	this->pool_size = pool_size;
	this->idle_threads = 0;
	this->threads = malloc(sizeof(pthread_t) * pool_size);
	
	/* try to create as many threads as possible, up to pool_size */
	for (current = 0; current < pool_size; current++)
	{
		if (pthread_create(&(this->threads[current]), NULL,
						   (void*(*)(void*))process_jobs, this) == 0)
		{
			DBG1(DBG_JOB, "created worker thread #%d", current+1);
		}
		else
		{
			/* creation failed, is it the first one? */	
			if (current == 0)
			{
				free(this->threads);
				free(this);
				charon->kill(charon, "could not create any worker threads");
			}
			/* not all threads could be created, but at least one :-/ */
			DBG1(DBG_JOB, "could only create %d from requested %d threads!",
				 current, pool_size);
			this->pool_size = current;
			break;
		}
	}
	return (thread_pool_t*)this;
}
