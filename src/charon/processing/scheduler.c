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
 *
 * $Id$
 */

#include <stdlib.h>
#include <pthread.h>
#include <sys/time.h>

#include "scheduler.h"

#include <daemon.h>
#include <processing/processor.h>
#include <processing/jobs/callback_job.h>

typedef struct event_t event_t;

/**
 * Event containing a job and a schedule time
 */
struct event_t {
	/**
	 * Time to fire the event.
	 */
	timeval_t time;

	/**
	 * Every event has its assigned job.
	 */
	job_t *job;
};

/**
 * destroy an event and its job
 */
static void event_destroy(event_t *event)
{
	event->job->destroy(event->job);
	free(event);
}

typedef struct private_scheduler_t private_scheduler_t;

/**
 * Private data of a scheduler_t object.
 */
struct private_scheduler_t {
	/**
	 * Public part of a scheduler_t object.
	 */
	 scheduler_t public;

	/**
	 * Job wich schedules
	 */
	callback_job_t *job;
	
	/**
	 * The jobs are scheduled in a list.
	 */
	linked_list_t *list;

	/**
	 * Exclusive access to list
	 */
	pthread_mutex_t mutex;

	/**
	 * Condvar to wait for next job.
	 */
	pthread_cond_t condvar;
	
	bool cancelled;
};

/**
 * Returns the difference of two timeval structs in milliseconds
 */
static long time_difference(timeval_t *end, timeval_t *start)
{
	time_t s;
	suseconds_t us;
	
	s = end->tv_sec - start->tv_sec;
	us = end->tv_usec - start->tv_usec;
	return (s * 1000 + us/1000);
}

/**
 * Get events from the queue and pass it to the processor
 */
static job_requeue_t schedule(private_scheduler_t * this)
{
	timespec_t timeout;
	timeval_t now;
	event_t *event;
	long difference;
	int oldstate;
	bool timed = FALSE;
	
	DBG2(DBG_JOB, "waiting for next event...");
	pthread_mutex_lock(&this->mutex);
	
	gettimeofday(&now, NULL);
	
	if (this->list->get_count(this->list) > 0)
	{
		this->list->get_first(this->list, (void **)&event);
		difference = time_difference(&now, &event->time);
		if (difference > 0)
		{
			DBG2(DBG_JOB, "got event, queueing job for execution");
			this->list->remove_first(this->list, (void **)&event);	
			pthread_mutex_unlock(&this->mutex);
			charon->processor->queue_job(charon->processor, event->job);
			free(event);
			return JOB_REQUEUE_DIRECT;
		}
		timeout.tv_sec = event->time.tv_sec;
		timeout.tv_nsec = event->time.tv_usec * 1000;
		timed = TRUE;
	}
	pthread_cleanup_push((void*)pthread_mutex_unlock, &this->mutex);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	
	if (timed)
	{
		pthread_cond_timedwait(&this->condvar, &this->mutex, &timeout);
	}
	else
	{
		pthread_cond_wait(&this->condvar, &this->mutex);
	}
	pthread_setcancelstate(oldstate, NULL);
	pthread_cleanup_pop(TRUE);
	return JOB_REQUEUE_DIRECT;
}

/**
 * Implements scheduler_t.get_job_load
 */
static u_int get_job_load(private_scheduler_t *this)
{
	int count;
	pthread_mutex_lock(&this->mutex);
	count = this->list->get_count(this->list);
	pthread_mutex_unlock(&this->mutex);
	return count;
}

/**
 * Implements scheduler_t.schedule_job.
 */
static void schedule_job(private_scheduler_t *this, job_t *job, u_int32_t time)
{
	timeval_t now;
	event_t *event, *current;
	iterator_t *iterator;
	time_t s;
	suseconds_t us;
	
	event = malloc_thing(event_t);
	event->job = job;
	
	/* calculate absolute time */
	s = time / 1000;
	us = (time - s * 1000) * 1000;
	gettimeofday(&now, NULL);
	event->time.tv_usec = (now.tv_usec + us) % 1000000;
	event->time.tv_sec = now.tv_sec + (now.tv_usec + us)/1000000 + s;
	
	pthread_mutex_lock(&this->mutex);
	while(TRUE)
	{
		if (this->list->get_count(this->list) == 0)
		{
			this->list->insert_first(this->list,event);
			break;
		}

		this->list->get_last(this->list, (void**)&current);
		if (time_difference(&event->time, &current->time) >= 0)
		{	/* new event has to be fired after the last event in list */
			this->list->insert_last(this->list, event);
			break;
		}

		this->list->get_first(this->list, (void**)&current);
		if (time_difference(&event->time, &current->time) < 0)
		{	/* new event has to be fired before the first event in list */
			this->list->insert_first(this->list, event);
			break;
		}
		
		iterator = this->list->create_iterator(this->list, TRUE);
		/* first element has not to be checked (already done) */
		iterator->iterate(iterator, (void**)&current);
		while(iterator->iterate(iterator, (void**)&current))
		{
			if (time_difference(&event->time, &current->time) <= 0)
			{
				/* new event has to be fired before the current event in list */
				iterator->insert_before(iterator, event);
				break;
			}
		}
		iterator->destroy(iterator);
		break;
	}
	pthread_cond_signal(&this->condvar);
	pthread_mutex_unlock(&this->mutex);
}

/**
 * Implementation of scheduler_t.destroy.
 */
static void destroy(private_scheduler_t *this)
{
	this->cancelled = TRUE;
	this->job->cancel(this->job);
	this->list->destroy_function(this->list, (void*)event_destroy);
	free(this);
}

/*
 * Described in header.
 */
scheduler_t * scheduler_create()
{
	private_scheduler_t *this = malloc_thing(private_scheduler_t);
	
	this->public.get_job_load = (u_int (*) (scheduler_t *this)) get_job_load;
	this->public.schedule_job = (void (*) (scheduler_t *this, job_t *job, u_int32_t ms)) schedule_job;
	this->public.destroy = (void(*)(scheduler_t*)) destroy;
	
	this->list = linked_list_create();
	this->cancelled = FALSE;
	pthread_mutex_init(&this->mutex, NULL);
	pthread_cond_init(&this->condvar, NULL);
	
	this->job = callback_job_create((callback_job_cb_t)schedule, this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);
	
	return &this->public;
}

