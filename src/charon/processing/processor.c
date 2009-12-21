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
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "processor.h"

#include <daemon.h>
#include <threading/thread.h>
#include <threading/condvar.h>
#include <threading/mutex.h>
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
	 * All threads managed in the pool (including threads that have been
	 * cancelled, this allows to join them during destruction)
	 */
	linked_list_t *threads;

	/**
	 * The jobs are stored in a linked list
	 */
	linked_list_t *list;

	/**
	 * access to linked_list is locked through this mutex
	 */
	mutex_t *mutex;

	/**
	 * Condvar to wait for new jobs
	 */
	condvar_t *job_added;

	/**
	 * Condvar to wait for terminated threads
	 */
	condvar_t *thread_terminated;
};

static void process_jobs(private_processor_t *this);

/**
 * restart a terminated thread
 */
static void restart(private_processor_t *this)
{
	thread_t *thread;

	DBG2(DBG_JOB, "terminated worker thread, ID: %u", thread_current_id());

	/* respawn thread if required */
	this->mutex->lock(this->mutex);
	if (this->desired_threads < this->total_threads ||
		(thread = thread_create((thread_main_t)process_jobs, this)) == NULL)
	{
		this->total_threads--;
		this->thread_terminated->signal(this->thread_terminated);
	}
	else
	{
		this->threads->insert_last(this->threads, thread);
	}
	this->mutex->unlock(this->mutex);
}

/**
 * Process queued jobs, called by the worker threads
 */
static void process_jobs(private_processor_t *this)
{
	/* worker threads are not cancellable by default */
	thread_cancelability(FALSE);

	DBG2(DBG_JOB, "started worker thread, ID: %u", thread_current_id());

	this->mutex->lock(this->mutex);
	while (this->desired_threads >= this->total_threads)
	{
		job_t *job;

		if (this->list->get_count(this->list) == 0)
		{
			this->idle_threads++;
			this->job_added->wait(this->job_added, this->mutex);
			this->idle_threads--;
			continue;
		}
		this->list->remove_first(this->list, (void**)&job);
		this->mutex->unlock(this->mutex);
		/* terminated threads are restarted, so we have a constant pool */
		thread_cleanup_push((thread_cleanup_t)restart, this);
		job->execute(job);
		thread_cleanup_pop(FALSE);
		this->mutex->lock(this->mutex);
	}
	this->mutex->unlock(this->mutex);
	restart(this);
}

/**
 * Implementation of processor_t.get_total_threads.
 */
static u_int get_total_threads(private_processor_t *this)
{
	u_int count;
	this->mutex->lock(this->mutex);
	count = this->total_threads;
	this->mutex->unlock(this->mutex);
	return count;
}

/**
 * Implementation of processor_t.get_idle_threads.
 */
static u_int get_idle_threads(private_processor_t *this)
{
	u_int count;
	this->mutex->lock(this->mutex);
	count = this->idle_threads;
	this->mutex->unlock(this->mutex);
	return count;
}

/**
 * implements processor_t.get_job_load
 */
static u_int get_job_load(private_processor_t *this)
{
	u_int load;
	this->mutex->lock(this->mutex);
	load = this->list->get_count(this->list);
	this->mutex->unlock(this->mutex);
	return load;
}

/**
 * implements function processor_t.queue_job
 */
static void queue_job(private_processor_t *this, job_t *job)
{
	this->mutex->lock(this->mutex);
	this->list->insert_last(this->list, job);
	this->job_added->signal(this->job_added);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of processor_t.set_threads.
 */
static void set_threads(private_processor_t *this, u_int count)
{
	this->mutex->lock(this->mutex);
	if (count > this->total_threads)
	{	/* increase thread count */
		int i;
		thread_t *current;

		this->desired_threads = count;
		DBG1(DBG_JOB, "spawning %d worker threads", count - this->total_threads);
		for (i = this->total_threads; i < count; i++)
		{
			current = thread_create((thread_main_t)process_jobs, this);
			if (current)
			{
				this->threads->insert_last(this->threads, current);
				this->total_threads++;
			}
		}
	}
	else if (count < this->total_threads)
	{	/* decrease thread count */
		this->desired_threads = count;
	}
	this->job_added->broadcast(this->job_added);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of processor_t.destroy.
 */
static void destroy(private_processor_t *this)
{
	thread_t *current;
	set_threads(this, 0);
	this->mutex->lock(this->mutex);
	while (this->total_threads > 0)
	{
		this->job_added->broadcast(this->job_added);
		this->thread_terminated->wait(this->thread_terminated, this->mutex);
	}
	while (this->threads->remove_first(this->threads,
									   (void**)&current) == SUCCESS)
	{
		current->join(current);
	}
	this->mutex->unlock(this->mutex);
	this->thread_terminated->destroy(this->thread_terminated);
	this->job_added->destroy(this->job_added);
	this->mutex->destroy(this->mutex);
	this->list->destroy_offset(this->list, offsetof(job_t, destroy));
	this->threads->destroy(this->threads);
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
	this->threads = linked_list_create();
	this->mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	this->job_added = condvar_create(CONDVAR_TYPE_DEFAULT);
	this->thread_terminated = condvar_create(CONDVAR_TYPE_DEFAULT);
	this->total_threads = 0;
	this->desired_threads = 0;
	this->idle_threads = 0;

	return &this->public;
}

