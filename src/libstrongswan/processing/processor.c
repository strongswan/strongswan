/*
 * Copyright (C) 2005-2011 Martin Willi
 * Copyright (C) 2011 revosec AG
 * Copyright (C) 2008-2011 Tobias Brunner
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

#include <debug.h>
#include <threading/thread.h>
#include <threading/condvar.h>
#include <threading/mutex.h>
#include <threading/thread_value.h>
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
	 * Number of threads currently working, for each priority
	 */
	u_int working_threads[JOB_PRIO_MAX];

	/**
	 * All threads managed in the pool (including threads that have been
	 * cancelled, this allows to join them during destruction)
	 */
	linked_list_t *threads;

	/**
	 * A list of queued jobs for each priority
	 */
	linked_list_t *jobs[JOB_PRIO_MAX];

	/**
	 * Threads reserved for each priority
	 */
	int prio_threads[JOB_PRIO_MAX];

	/**
	 * Priority of the job executed by a thread
	 */
	thread_value_t *priority;

	/**
	 * access to job lists is locked through this mutex
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

	DBG2(DBG_JOB, "terminated worker thread %.2u", thread_current_id());

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
 * Decrement working thread count of a priority class
 */
static void decrement_working_threads(private_processor_t *this)
{
	this->mutex->lock(this->mutex);
	this->working_threads[(intptr_t)this->priority->get(this->priority)]--;
	this->mutex->unlock(this->mutex);
}

/**
 * Get number of idle threads, non-locking variant
 */
static u_int get_idle_threads_nolock(private_processor_t *this)
{
	u_int count, i;

	count = this->total_threads;
	for (i = 0; i < JOB_PRIO_MAX; i++)
	{
		count -= this->working_threads[i];
	}
	return count;
}

/**
 * Process queued jobs, called by the worker threads
 */
static void process_jobs(private_processor_t *this)
{
	/* worker threads are not cancellable by default */
	thread_cancelability(FALSE);

	DBG2(DBG_JOB, "started worker thread %.2u", thread_current_id());

	this->mutex->lock(this->mutex);
	while (this->desired_threads >= this->total_threads)
	{
		job_t *job = NULL;
		int i, reserved = 0, idle;

		idle = get_idle_threads_nolock(this);

		for (i = 0; i < JOB_PRIO_MAX; i++)
		{
			if (reserved && reserved >= idle)
			{
				DBG2(DBG_JOB, "delaying %N priority jobs: %d threads idle, "
					 "but %d reserved for higher priorities",
					 job_priority_names, i, idle, reserved);
				break;
			}
			if (this->working_threads[i] < this->prio_threads[i])
			{
				reserved += this->prio_threads[i] - this->working_threads[i];
			}
			if (this->jobs[i]->remove_first(this->jobs[i],
											(void**)&job) == SUCCESS)
			{
				this->working_threads[i]++;
				this->mutex->unlock(this->mutex);
				this->priority->set(this->priority, (void*)(intptr_t)i);
				/* terminated threads are restarted to get a constant pool */
				thread_cleanup_push((thread_cleanup_t)restart, this);
				thread_cleanup_push((thread_cleanup_t)decrement_working_threads,
									this);
				job->execute(job);
				thread_cleanup_pop(FALSE);
				thread_cleanup_pop(FALSE);
				this->mutex->lock(this->mutex);
				this->working_threads[i]--;
				break;
			}
		}
		if (!job)
		{
			this->job_added->wait(this->job_added, this->mutex);
		}
	}
	this->total_threads--;
	this->thread_terminated->signal(this->thread_terminated);
	this->mutex->unlock(this->mutex);
}

METHOD(processor_t, get_total_threads, u_int,
	private_processor_t *this)
{
	u_int count;

	this->mutex->lock(this->mutex);
	count = this->total_threads;
	this->mutex->unlock(this->mutex);
	return count;
}

METHOD(processor_t, get_idle_threads, u_int,
	private_processor_t *this)
{
	u_int count;

	this->mutex->lock(this->mutex);
	count = get_idle_threads_nolock(this);
	this->mutex->unlock(this->mutex);
	return count;
}

/**
 * Check priority bounds
 */
static job_priority_t sane_prio(job_priority_t prio)
{
	if ((int)prio < 0 || prio >= JOB_PRIO_MAX)
	{
		return JOB_PRIO_MAX - 1;
	}
	return prio;
}

METHOD(processor_t, get_working_threads, u_int,
	private_processor_t *this, job_priority_t prio)
{
	u_int count;

	this->mutex->lock(this->mutex);
	count = this->working_threads[sane_prio(prio)];
	this->mutex->unlock(this->mutex);
	return count;
}

METHOD(processor_t, get_job_load, u_int,
	private_processor_t *this, job_priority_t prio)
{
	u_int load;

	prio = sane_prio(prio);
	this->mutex->lock(this->mutex);
	load = this->jobs[prio]->get_count(this->jobs[prio]);
	this->mutex->unlock(this->mutex);
	return load;
}

METHOD(processor_t, queue_job, void,
	private_processor_t *this, job_t *job)
{
	job_priority_t prio;

	prio = sane_prio(job->get_priority(job));
	this->mutex->lock(this->mutex);
	this->jobs[prio]->insert_last(this->jobs[prio], job);
	this->job_added->signal(this->job_added);
	this->mutex->unlock(this->mutex);
}

METHOD(processor_t, set_threads, void,
	private_processor_t *this, u_int count)
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

METHOD(processor_t, destroy, void,
	private_processor_t *this)
{
	thread_t *current;
	int i;

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
	this->priority->destroy(this->priority);
	this->thread_terminated->destroy(this->thread_terminated);
	this->job_added->destroy(this->job_added);
	this->mutex->destroy(this->mutex);
	for (i = 0; i < JOB_PRIO_MAX; i++)
	{
		this->jobs[i]->destroy_offset(this->jobs[i], offsetof(job_t, destroy));
	}
	this->threads->destroy(this->threads);
	free(this);
}

/*
 * Described in header.
 */
processor_t *processor_create()
{
	private_processor_t *this;
	int i;

	INIT(this,
		.public = {
			.get_total_threads = _get_total_threads,
			.get_idle_threads = _get_idle_threads,
			.get_working_threads = _get_working_threads,
			.get_job_load = _get_job_load,
			.queue_job = _queue_job,
			.set_threads = _set_threads,
			.destroy = _destroy,
		},
		.threads = linked_list_create(),
		.priority = thread_value_create(NULL),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.job_added = condvar_create(CONDVAR_TYPE_DEFAULT),
		.thread_terminated = condvar_create(CONDVAR_TYPE_DEFAULT),
	);
	for (i = 0; i < JOB_PRIO_MAX; i++)
	{
		this->jobs[i] = linked_list_create();
		this->prio_threads[i] = lib->settings->get_int(lib->settings,
						"libstrongswan.processor.priority_threads.%N", 0,
						job_priority_names, i);
	}

	return &this->public;
}

