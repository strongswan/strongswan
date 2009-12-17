/*
 * Copyright (C) 2009 Tobias Brunner
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

#include <semaphore.h>

#include <daemon.h>
#include <threading/thread.h>
#include <threading/condvar.h>
#include <threading/mutex.h>

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
	 * thread of the job, if running
	 */
	thread_t *thread;

	/**
	 * mutex to access jobs interna
	 */
	mutex_t *mutex;

	/**
	 * list of asociated child jobs
	 */
	linked_list_t *children;

	/**
	 * parent of this job, or NULL
	 */
	private_callback_job_t *parent;

	/**
	 * TRUE if the job got cancelled
	 */
	bool cancelled;

	/**
	 * condvar to synchronize the cancellation/destruction of the job
	 */
	condvar_t *destroyable;

	/**
	 * semaphore to synchronize the termination of the assigned thread.
	 *
	 * separately allocated during cancellation, so that we can wait on it
	 * without risking that it gets freed too early during destruction.
	 */
	sem_t *terminated;
};

/**
 * unregister a child from its parent, if any.
 * note: this->mutex has to be locked
 */
static void unregister(private_callback_job_t *this)
{
	if (this->parent)
	{
		this->parent->mutex->lock(this->parent->mutex);
		if (this->parent->cancelled && !this->cancelled)
		{
			/* if the parent has been cancelled but we have not yet, we do not
			 * unregister until we got cancelled by the parent. */
			this->parent->mutex->unlock(this->parent->mutex);
			this->destroyable->wait(this->destroyable, this->mutex);
			this->parent->mutex->lock(this->parent->mutex);
		}
		this->parent->children->remove(this->parent->children, this, NULL);
		this->parent->mutex->unlock(this->parent->mutex);
		this->parent = NULL;
	}
}

/**
 * Implements job_t.destroy.
 */
static void destroy(private_callback_job_t *this)
{
	this->mutex->lock(this->mutex);
	unregister(this);
	if (this->cleanup)
	{
		this->cleanup(this->data);
	}
	if (this->terminated)
	{
		sem_post(this->terminated);
	}
	this->children->destroy(this->children);
	this->destroyable->destroy(this->destroyable);
	this->mutex->unlock(this->mutex);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * Implementation of callback_job_t.cancel.
 */
static void cancel(private_callback_job_t *this)
{
	callback_job_t *child;
	sem_t *terminated = NULL;

	this->mutex->lock(this->mutex);
	this->cancelled = TRUE;
	/* terminate children */
	while (this->children->get_first(this->children, (void**)&child) == SUCCESS)
	{
		this->mutex->unlock(this->mutex);
		child->cancel(child);
		this->mutex->lock(this->mutex);
	}
	if (this->thread)
	{
		/* terminate the thread, if there is currently one executing the job.
		 * we wait for its termination using a semaphore */
		this->thread->cancel(this->thread);
		terminated = this->terminated = malloc_thing(sem_t);
		sem_init(terminated, 0, 0);
	}
	else
	{
		/* if the job is currently queued, it gets terminated later.
		 * we can't wait, because it might not get executed at all.
		 * we also unregister the queued job manually from its parent (the
		 * others get unregistered during destruction) */
		unregister(this);
	}
	this->destroyable->signal(this->destroyable);
	this->mutex->unlock(this->mutex);

	if (terminated)
	{
		sem_wait(terminated);
		sem_destroy(terminated);
		free(terminated);
	}
}

/**
 * Implementation of job_t.execute.
 */
static void execute(private_callback_job_t *this)
{
	bool cleanup = FALSE;

	thread_cleanup_push((thread_cleanup_t)destroy, this);

	this->mutex->lock(this->mutex);
	this->thread = thread_current();
	this->mutex->unlock(this->mutex);

	while (TRUE)
	{
		this->mutex->lock(this->mutex);
		if (this->cancelled)
		{
			this->mutex->unlock(this->mutex);
			cleanup = TRUE;
			break;
		}
		this->mutex->unlock(this->mutex);
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
	this->mutex->lock(this->mutex);
	this->thread = NULL;
	this->mutex->unlock(this->mutex);
	/* manually create a cancellation point to avoid that a cancelled thread
	 * goes back into the thread pool */
	thread_cancellation_point();
	thread_cleanup_pop(cleanup);
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
	this->mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	this->callback = cb;
	this->data = data;
	this->cleanup = cleanup;
	this->thread = 0;
	this->children = linked_list_create();
	this->parent = (private_callback_job_t*)parent;
	this->cancelled = FALSE;
	this->destroyable = condvar_create(CONDVAR_TYPE_DEFAULT);
	this->terminated = NULL;

	/* register us at parent */
	if (parent)
	{
		this->parent->mutex->lock(this->parent->mutex);
		this->parent->children->insert_last(this->parent->children, this);
		this->parent->mutex->unlock(this->parent->mutex);
	}

	return &this->public;
}

