/**
 * @file job_queue.c
 *
 * @brief Implementation of job_queue_t
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

#include "job_queue.h"

#include <utils/linked_list.h>


typedef struct private_job_queue_t private_job_queue_t;

/**
 * @brief Private Variables and Functions of job_queue class
 *
 */
struct private_job_queue_t {
	
	/**
	 * public members
	 */
 	job_queue_t public;

	/**
	 * The jobs are stored in a linked list
	 */
	linked_list_t *list;
	
	/**
	 * access to linked_list is locked through this mutex
	 */
	pthread_mutex_t mutex;

	/**
	 * If the queue is empty a thread has to wait
	 * This condvar is used to wake up such a thread
	 */
	pthread_cond_t condvar;
};


/**
 * implements job_queue_t.get_count
 */
static int get_count(private_job_queue_t *this)
{
	int count;
	pthread_mutex_lock(&(this->mutex));
	count = this->list->get_count(this->list);
	pthread_mutex_unlock(&(this->mutex));
	return count;
}

/**
 * implements job_queue_t.get
 */
static job_t *get(private_job_queue_t *this)
{
	int oldstate;
	job_t *job;
	pthread_mutex_lock(&(this->mutex));
	/* go to wait while no jobs available */
	while(this->list->get_count(this->list) == 0)
	{
		/* add mutex unlock handler for cancellation, enable cancellation */
		pthread_cleanup_push((void(*)(void*))pthread_mutex_unlock, (void*)&(this->mutex));
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
		
		pthread_cond_wait( &(this->condvar), &(this->mutex));
		
		/* reset cancellation, remove mutex-unlock handler (without executing) */
		pthread_setcancelstate(oldstate, NULL);
		pthread_cleanup_pop(0);
	}
	this->list->remove_first(this->list, (void **)&job);
	pthread_mutex_unlock(&(this->mutex));
	return job;
}

/**
 * implements function job_queue_t.add
 */
static void add(private_job_queue_t *this, job_t *job)
{
	pthread_mutex_lock(&(this->mutex));
	this->list->insert_last(this->list,job);
	pthread_cond_signal( &(this->condvar));
	pthread_mutex_unlock(&(this->mutex));
}

/**
 * implements job_queue_t.destroy
 */
static void job_queue_destroy (private_job_queue_t *this)
{
	job_t *job;
	while (this->list->remove_last(this->list, (void**)&job) == SUCCESS)
	{
		job->destroy(job);
	}
	this->list->destroy(this->list);
	pthread_mutex_destroy(&(this->mutex));
	pthread_cond_destroy(&(this->condvar));
	free(this);
}

/*
 *
 * Documented in header
 */
job_queue_t *job_queue_create(void)
{
	private_job_queue_t *this = malloc_thing(private_job_queue_t);

	this->public.get_count = (int(*)(job_queue_t*))get_count;
	this->public.get = (job_t*(*)(job_queue_t*))get;
	this->public.add = (void(*)(job_queue_t*, job_t*))add;
	this->public.destroy = (void(*)(job_queue_t*))job_queue_destroy;

	this->list = linked_list_create();
	pthread_mutex_init(&(this->mutex), NULL);
	pthread_cond_init(&(this->condvar), NULL);

	return (&this->public);
}
