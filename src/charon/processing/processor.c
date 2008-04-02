/*
 * Copyright (C) 2005-2007 Martin Willi
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
 *
 * $Id$
 */
 
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

#include "processor.h"

#include <daemon.h>
#include <utils/linked_list.h>


typedef struct private_processor_t private_processor_t;

/**
 * Private data of processor_t class.
 */
struct private_processor_t {
	/**
	 * Public processor_t interface.
	 */
	processor_t public;

	/**
	 * Number of running threads
	 */
	u_int total_threads;
	
	/**
	 * Desired number of threads
	 */
	u_int desired_threads;
	
	/**
	 * Number of threads waiting for work
	 */
	u_int idle_threads;

	/**
	 * The jobs are stored in a linked list
	 */
	linked_list_t *list;
	
	/**
	 * access to linked_list is locked through this mutex
	 */
	pthread_mutex_t mutex;

	/**
	 * Condvar to wait for new jobs
	 */
	pthread_cond_t condvar;
};

static void process_jobs(private_processor_t *this);

/**
 * restart a terminated thread
 */
static void restart(private_processor_t *this)
{
	pthread_t thread;
	
	if (pthread_create(&thread, NULL, (void*)process_jobs, this) != 0)
	{
		this->total_threads--;
	}
}

/**
 * Process queued jobs, called by the worker threads
 */
static void process_jobs(private_processor_t *this)
{
	int oldstate;
	
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
	
	DBG2(DBG_JOB, "started worker thread, thread_ID: %06u", (int)pthread_self());
	
	pthread_mutex_lock(&this->mutex);
	while (this->desired_threads >= this->total_threads)
	{
		job_t *job;
		
		if (this->list->get_count(this->list) == 0)
		{
			this->idle_threads++;
			pthread_cond_wait(&this->condvar, &this->mutex);
			this->idle_threads--;
			continue;
		}
		this->list->remove_first(this->list, (void**)&job);
		pthread_mutex_unlock(&this->mutex);
		/* terminated threads are restarted, so we have a constant pool */
		pthread_cleanup_push((void*)restart, this);
		job->execute(job);
		pthread_cleanup_pop(0);
		pthread_mutex_lock(&this->mutex);
	}
	this->total_threads--;
	pthread_cond_broadcast(&this->condvar);
	pthread_mutex_unlock(&this->mutex);
}

/**
 * Implementation of processor_t.get_total_threads.
 */
static u_int get_total_threads(private_processor_t *this)
{
	return this->total_threads;
}

/**
 * Implementation of processor_t.get_idle_threads.
 */
static u_int get_idle_threads(private_processor_t *this)
{
	return this->idle_threads;
}

/**
 * implements processor_t.get_job_load
 */
static u_int get_job_load(private_processor_t *this)
{
	u_int load;
	pthread_mutex_lock(&this->mutex);
	load = this->list->get_count(this->list);
	pthread_mutex_unlock(&this->mutex);
	return load;
}

/**
 * implements function processor_t.queue_job
 */
static void queue_job(private_processor_t *this, job_t *job)
{
	pthread_mutex_lock(&this->mutex);
	this->list->insert_last(this->list, job);
	pthread_mutex_unlock(&this->mutex);
	pthread_cond_signal(&this->condvar);
}
	
/**
 * Implementation of processor_t.set_threads.
 */
static void set_threads(private_processor_t *this, u_int count)
{
	pthread_mutex_lock(&this->mutex);
	if (count > this->total_threads)
	{	/* increase thread count */
		int i;
		pthread_t current;
		
		this->desired_threads = count;
		DBG1(DBG_JOB, "spawning %d worker threads", count - this->total_threads);
		for (i = this->total_threads; i < count; i++)
		{
			if (pthread_create(&current, NULL, (void*)process_jobs, this) == 0)
			{
				this->total_threads++;
			}
		}
	}
	else if (count < this->total_threads)
	{	/* decrease thread count */
		this->desired_threads = count;
	}
	pthread_mutex_unlock(&this->mutex);
}

/**
 * Implementation of processor_t.destroy.
 */
static void destroy(private_processor_t *this)
{
	set_threads(this, 0);
	pthread_mutex_lock(&this->mutex);
	while (this->total_threads > 0)
	{
		pthread_cond_broadcast(&this->condvar);
		pthread_cond_wait(&this->condvar, &this->mutex);
	}
	pthread_mutex_unlock(&this->mutex);
	this->list->destroy_offset(this->list, offsetof(job_t, destroy));
	free(this);
}

/*
 * Described in header.
 */
processor_t *processor_create(size_t pool_size)
{
	private_processor_t *this = malloc_thing(private_processor_t);
	
	this->public.get_total_threads = (u_int(*)(processor_t*))get_total_threads;
	this->public.get_idle_threads = (u_int(*)(processor_t*))get_idle_threads;
	this->public.get_job_load = (u_int(*)(processor_t*))get_job_load;
	this->public.queue_job = (void(*)(processor_t*, job_t*))queue_job;
	this->public.set_threads = (void(*)(processor_t*, u_int))set_threads;
	this->public.destroy = (void(*)(processor_t*))destroy;
	
	this->list = linked_list_create();
	pthread_mutex_init(&this->mutex, NULL);
	pthread_cond_init(&this->condvar, NULL);
	this->total_threads = 0;
	this->desired_threads = 0;
	this->idle_threads = 0;
	
	return &this->public;
}

