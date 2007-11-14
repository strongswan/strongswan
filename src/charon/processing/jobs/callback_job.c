/**
 * @file callback_job.c
 * 
 * @brief Implementation of callback_job_t.
 * 
 */

/*
 * Copyright (C) 2007 Martin Willi
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
 
#include "callback_job.h"

#include <daemon.h>

typedef struct private_callback_job_t private_callback_job_t;

/**
 * Private data of an callback_job_t Object.
 */
struct private_callback_job_t {
	/**
	 * Public callback_job_t interface.
	 */
	callback_job_t public;
	
	/**
	 * Callback to call on execution
	 */
	callback_job_cb_t callback;

	/**
	 * parameter to supply to callback
	 */
	void *data;
	
	/**
	 * cleanup function for data
	 */
	callback_job_cleanup_t cleanup;
	
	/**
	 * thread ID of the job, if running
	 */
	pthread_t thread;

	/**
	 * mutex to access jobs interna
	 */
	pthread_mutex_t mutex;

	/**
	 * condvar to synchronize thread startup/cancellation
	 */
	pthread_cond_t condvar;
	
	/**
	 * list of asociated child jobs
	 */
	linked_list_t *children;
	
	/**
	 * parent of this job, or NULL
	 */
	private_callback_job_t *parent;
};

/**
 * Implements job_t.destroy.
 */
static void destroy(private_callback_job_t *this)
{
	if (this->cleanup)
	{
		this->cleanup(this->data);
	}
	this->children->destroy(this->children);
	free(this);
}

/**
 * unregister a child from its parent, if any.
 */
static void unregister(private_callback_job_t *this)
{
	if (this->parent)
	{
		iterator_t *iterator;
		private_callback_job_t *child;
		
		pthread_mutex_lock(&this->parent->mutex);
		iterator = this->parent->children->create_iterator(this->parent->children, TRUE);
		while (iterator->iterate(iterator, (void**)&child))
		{
			if (child == this)
			{
				iterator->remove(iterator);
				break;
			}
		}
		iterator->destroy(iterator);
		pthread_mutex_unlock(&this->parent->mutex);
	}
}

/**
 * Implementation of callback_job_t.cancel.
 */
static void cancel(private_callback_job_t *this)
{
	pthread_t thread;
	
	pthread_mutex_lock(&this->mutex);
	thread = this->thread;
	
	/* terminate its children */
	this->children->invoke_offset(this->children, offsetof(callback_job_t, cancel));
	pthread_mutex_unlock(&this->mutex);
	
	/* terminate thread */
	if (thread)
	{
		pthread_cancel(thread);
		pthread_join(thread, NULL);
	}
}

/**
 * Implementation of job_t.execute.
 */
static void execute(private_callback_job_t *this)
{
	bool cleanup = FALSE;

	pthread_mutex_lock(&this->mutex);
	this->thread = pthread_self();
	pthread_cond_signal(&this->condvar);
	pthread_mutex_unlock(&this->mutex);
	
	pthread_cleanup_push((void*)destroy, this);
	while (TRUE)
	{
		switch (this->callback(this->data))
		{
			case JOB_REQUEUE_DIRECT:
				continue;
			case JOB_REQUEUE_FAIR:
			{
				charon->processor->queue_job(charon->processor,
											 &this->public.job_interface);
				break;
			}
			case JOB_REQUEUE_NONE:
			default:
			{
				cleanup = TRUE;
				break;
			}
		}
		break;
	}
	unregister(this);
	pthread_cleanup_pop(cleanup);
}

/*
 * Described in header.
 */
callback_job_t *callback_job_create(callback_job_cb_t cb, void *data,
									callback_job_cleanup_t cleanup,
									callback_job_t *parent)
{
	private_callback_job_t *this = malloc_thing(private_callback_job_t);
	
	/* interface functions */
	this->public.job_interface.execute = (void (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void (*) (job_t *)) destroy;
	this->public.cancel = (void(*)(callback_job_t*))cancel;

	/* private variables */
	pthread_mutex_init(&this->mutex, NULL);
	pthread_cond_init(&this->condvar, NULL);
	this->callback = cb;
	this->data = data;
	this->cleanup = cleanup;
	this->thread = 0;
	this->children = linked_list_create();
	this->parent = (private_callback_job_t*)parent;
	
	/* register us at parent */
	if (parent)
	{
		pthread_mutex_lock(&this->parent->mutex);
		this->parent->children->insert_last(this->parent->children, this);
		pthread_mutex_unlock(&this->parent->mutex);
	}
	
	return &this->public;
}

