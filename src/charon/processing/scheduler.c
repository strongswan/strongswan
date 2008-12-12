/*
 * Copyright (C) 2008 Tobias Brunner
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
#include <utils/mutex.h>

/* the initial size of the heap */
#define HEAP_SIZE_DEFAULT 64

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
	 * Job which queues scheduled jobs to the processor.
	 */
	callback_job_t *job;
		
	/**
	 * The heap in which the events are stored.
	 */
	event_t **heap;
	
	/**
	 * The size of the heap.
	 */
	u_int heap_size;
	
	/**
	 * The number of scheduled events.
	 */
	u_int event_count;

	/**
	 * Exclusive access to list
	 */
	mutex_t *mutex;

	/**
	 * Condvar to wait for next job.
	 */
	condvar_t *condvar;
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
 * Returns the top event without removing it. Returns NULL if the heap is empty.
 */
static event_t *peek_event(private_scheduler_t *this)
{
	return this->event_count > 0 ? this->heap[1] : NULL;
}

/**
 * Removes the top event from the heap and returns it. Returns NULL if the heap
 * is empty.
 */
static event_t *remove_event(private_scheduler_t *this)
{
	event_t *event, *top;
	if (!this->event_count)
	{
		return NULL;
	}
	
	/* store the value to return */
	event = this->heap[1];
	/* move the bottom event to the top */
	top = this->heap[1] = this->heap[this->event_count];
		
	if (--this->event_count > 1)
	{
		/* seep down the top event */
		u_int position = 1;
		while ((position << 1) <= this->event_count)
		{
			u_int child = position << 1;
			
			if ((child + 1) <= this->event_count &&
				time_difference(&this->heap[child + 1]->time,
								&this->heap[child]->time) < 0)
			{
				/* the "right" child is smaller */
				child++;
			}
			
			if (time_difference(&top->time, &this->heap[child]->time) <= 0)
			{
				/* the top event fires before the smaller of the two children, stop */
				break;
			}
			
			/* exchange with the smaller child */
			this->heap[position] = this->heap[child];
			position = child;
		}
		this->heap[position] = top;
	}
	return event;
}

/**
 * Get events from the queue and pass it to the processor
 */
static job_requeue_t schedule(private_scheduler_t * this)
{
	timeval_t now;
	event_t *event;
	long difference;
	int oldstate;
	bool timed = FALSE;
	
	this->mutex->lock(this->mutex);
	
	gettimeofday(&now, NULL);
	
	if ((event = peek_event(this)) != NULL)
	{
		difference = time_difference(&now, &event->time);
		if (difference >= 0)
		{
			remove_event(this);
			this->mutex->unlock(this->mutex);
			DBG2(DBG_JOB, "got event, queuing job for execution");
			charon->processor->queue_job(charon->processor, event->job);
			free(event);
			return JOB_REQUEUE_DIRECT;
		}
		DBG2(DBG_JOB, "next event in %ldms, waiting", -difference);
		timed = TRUE;
	}
	pthread_cleanup_push((void*)this->mutex->unlock, this->mutex);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	
	if (timed)
	{
		this->condvar->timed_wait_abs(this->condvar, this->mutex, event->time);
	}
	else
	{
		DBG2(DBG_JOB, "no events, waiting");
		this->condvar->wait(this->condvar, this->mutex);
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
	this->mutex->lock(this->mutex);
	count = this->event_count;
	this->mutex->unlock(this->mutex);
	return count;
}

/**
 * Implements scheduler_t.schedule_job.
 */
static void schedule_job(private_scheduler_t *this, job_t *job, u_int32_t time)
{
	timeval_t now;
	event_t *event;
	u_int position;
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
	
	this->mutex->lock(this->mutex);
	
	this->event_count++;
	if (this->event_count > this->heap_size)
	{
		/* double the size of the heap */
		this->heap_size <<= 1;
		this->heap = (event_t**)realloc(this->heap, (this->heap_size + 1) * sizeof(event_t*));
	}
	/* "put" the event to the bottom */
	position = this->event_count;
	
	/* then bubble it up */
	while (position > 1 && time_difference(&this->heap[position >> 1]->time,
										   &event->time) > 0)
	{
		/* parent has to be fired after the new event, move up */
		this->heap[position] = this->heap[position >> 1];
		position >>= 1;
	}
	this->heap[position] = event;
	
	this->condvar->signal(this->condvar);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of scheduler_t.destroy.
 */
static void destroy(private_scheduler_t *this)
{
	event_t *event;
	this->job->cancel(this->job);
	this->condvar->destroy(this->condvar);
	this->mutex->destroy(this->mutex);
	while ((event = remove_event(this)) != NULL)
	{
		event_destroy(event);
	}
	free(this->heap);
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
	
	/* Note: the root of the heap is at index 1 */
	this->event_count = 0;
	this->heap_size = HEAP_SIZE_DEFAULT;
	this->heap = (event_t**)calloc(this->heap_size + 1, sizeof(event_t*));
	
	this->mutex = mutex_create(MUTEX_DEFAULT);
	this->condvar = condvar_create(CONDVAR_DEFAULT);
	
	this->job = callback_job_create((callback_job_cb_t)schedule, this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);
	
	return &this->public;
}

