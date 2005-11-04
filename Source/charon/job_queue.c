/**
 * @file job_queue.c
 * 
 * @brief Job-Queue based on linked_list_t
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

//#include <stdlib.h>
#include <pthread.h>
#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>
	
#include "job_queue.h"

/**
 * @brief implements function destroy of job_t
 */
static status_t job_destroy(job_t *job)
{
	pfree(job);
	return SUCCESS;
}

/*
 * Creates a job (documented in header-file)
 */
job_t *job_create(job_type_t type, void *assigned_data)
{
	job_t *this = alloc_thing(job_t, "job_t");

	this->destroy = job_destroy;

	this->type = type;
	this->assigned_data = assigned_data;
	
	return this;
}

/**
 * @brief Private Variables and Functions of job_queue class
 * 
 */
typedef struct private_job_queue_s private_job_queue_t;
 

struct private_job_queue_s {
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
 * @brief implements function get_count of job_queue_t
 */
status_t get_count(private_job_queue_t *this, int *count)
{
	pthread_mutex_lock(&(this->mutex));
	*count = this->list->count;
	pthread_mutex_unlock(&(this->mutex));
	return SUCCESS;
}

/**
 * @brief implements function get of job_queue_t
 */
status_t get(private_job_queue_t *this, job_t **job)
{
	pthread_mutex_lock(&(this->mutex));
	// add mutex unlock handler for cancellation
	pthread_cleanup_push((void(*)(void*))pthread_mutex_unlock, (void*)&(this->mutex));
	// go to wait while no jobs available
	while(this->list->count == 0)
	{
		pthread_cond_wait( &(this->condvar), &(this->mutex));
	}
	// remove mutex-unlock handler (without executing)
	pthread_cleanup_pop(0);
	
	this->list->remove_first(this->list,(void **) job);
	pthread_mutex_unlock(&(this->mutex));
	return SUCCESS;
}

/**
 * @brief implements function add of job_queue_t
 */
status_t add(private_job_queue_t *this, job_t *job)
{
	pthread_mutex_lock(&(this->mutex));
	this->list->insert_last(this->list,job);
	pthread_cond_signal( &(this->condvar));
	pthread_mutex_unlock(&(this->mutex));
	return SUCCESS;
}

/**
 * @brief implements function destroy of job_queue_t
 * 
 */
status_t job_queue_destroy (private_job_queue_t *this)
{	
	while (this->list->count > 0) 
	{
		job_t *job;
		if (this->list->remove_first(this->list,(void *) &job) != SUCCESS)
		{
			this->list->destroy(this->list);
			break;
		}
		job->destroy(job);
	}
	this->list->destroy(this->list);
	
	pthread_mutex_destroy(&(this->mutex));
	
	pthread_cond_destroy(&(this->condvar));
	
	pfree(this);
	return SUCCESS;
}

/*
 * 
 * Documented in header
 */
job_queue_t *job_queue_create()
{
	linked_list_t *linked_list = linked_list_create();
	if (linked_list == NULL)
	{
		return NULL;
	}
	
	private_job_queue_t *this = alloc_thing(private_job_queue_t, "private_job_queue_t");
	if (this == NULL)
	{
		linked_list->destroy(linked_list);
		return NULL;
	}
	
	this->public.get_count = (status_t(*)(job_queue_t*, int*))get_count;
	this->public.get = (status_t(*)(job_queue_t*, job_t**))get;
	this->public.add = (status_t(*)(job_queue_t*, job_t*))add;
	this->public.destroy = (status_t(*)(job_queue_t*))job_queue_destroy;
	
	this->list = linked_list;
	pthread_mutex_init(&(this->mutex), NULL);
	pthread_cond_init(&(this->condvar), NULL);
	
	return (&this->public);
}
