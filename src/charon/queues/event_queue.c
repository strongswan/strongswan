/**
 * @file event_queue.c
 *
 * @brief Implementation of event_queue_t
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

#include <pthread.h>
#include <stdlib.h>

#include "event_queue.h"

#include <types.h>
#include <utils/linked_list.h>



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
	job_t * job;
};

typedef struct private_event_queue_t private_event_queue_t;

/**
 * Private Variables and Functions of event_queue_t class.
 */
struct private_event_queue_t {
	/**
	 * Public part.
	 */
 	event_queue_t public;

	/**
	 * The events are stored in a linked list of type linked_list_t.
	 */
	linked_list_t *list;

	/**
	 * Access to linked_list is locked through this mutex.
	 */
	pthread_mutex_t mutex;

	/**
	 * If the queue is empty or an event has not to be fired
	 * a thread has to wait.
	 * 
	 * This condvar is used to wake up such a thread.
	 */
	pthread_cond_t condvar;
};

/**
 * Returns the difference of to timeval structs in milliseconds
 */
static long time_difference(struct timeval *end_time, struct timeval *start_time)
{
	time_t s;
	suseconds_t us;
	
	s = (end_time->tv_sec - start_time->tv_sec);
	us = (end_time->tv_usec - start_time->tv_usec);
	return ((s * 1000) + us/1000);
}

/**
 * Implements event_queue_t.get_count
 */
static int get_count(private_event_queue_t *this)
{
	int count;
	pthread_mutex_lock(&(this->mutex));
	count = this->list->get_count(this->list);
	pthread_mutex_unlock(&(this->mutex));
	return count;
}

/**
 * Implements event_queue_t.get
 */
static job_t *get(private_event_queue_t *this)
{
	timespec_t timeout;
	timeval_t current_time;
	event_t * next_event;
	job_t *job;
	int oldstate;
	
	pthread_mutex_lock(&(this->mutex));
	
	while (TRUE)
	{
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
		
		this->list->get_first(this->list, (void **)&next_event);
		
		gettimeofday(&current_time, NULL);
		long difference = time_difference(&current_time,&(next_event->time));
		if (difference <= 0)
		{
			timeout.tv_sec = next_event->time.tv_sec;
			timeout.tv_nsec = next_event->time.tv_usec * 1000;
			
			/* add mutex unlock handler for cancellation, enable cancellation */
			pthread_cleanup_push((void(*)(void*))pthread_mutex_unlock, (void*)&(this->mutex));
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
			
			pthread_cond_timedwait(&(this->condvar), &(this->mutex), &timeout);
			
			/* reset cancellation, remove mutex-unlock handler (without executing) */
			pthread_setcancelstate(oldstate, NULL);
			pthread_cleanup_pop(0);
		}
		else
		{
			/* event available */
			this->list->remove_first(this->list, (void **)&next_event);
			job = next_event->job;
			free(next_event);
			break;
		}
	}
	pthread_cond_signal( &(this->condvar));
	pthread_mutex_unlock(&(this->mutex));
	
	return job;
}

/**
 * Implements function add_absolute of event_queue_t.
 * See #event_queue_s.add_absolute for description.
 */
static void add_absolute(private_event_queue_t *this, job_t *job, timeval_t time)
{
	event_t *event;
	event_t *current_event;
	status_t status;
	
	/* create event */
	event = malloc_thing(event_t);
	event->time = time;
	event->job = job;

	pthread_mutex_lock(&(this->mutex));

	/* while just used to break out */
	while(1)
	{
		if (this->list->get_count(this->list) == 0)
		{
			this->list->insert_first(this->list,event);
			break;
		}

		/* check last entry */
		this->list->get_last(this->list,(void **) &current_event);

		if (time_difference(&(event->time), &(current_event->time)) >= 0)
		{
			/* my event has to be fired after the last event in list */
			this->list->insert_last(this->list,event);
			break;
		}

		/* check first entry */
		this->list->get_first(this->list,(void **) &current_event);

		if (time_difference(&(event->time), &(current_event->time)) < 0)
		{
			/* my event has to be fired before the first event in list */
			this->list->insert_first(this->list,event);
			break;
		}

		iterator_t * iterator;

		iterator = this->list->create_iterator(this->list,TRUE);

		iterator->has_next(iterator);
		/* first element has not to be checked (already done) */

		while(iterator->has_next(iterator))
		{
			status = iterator->current(iterator,(void **) &current_event);

			if (time_difference(&(event->time), &(current_event->time)) <= 0)
			{
				/* my event has to be fired before the current event in list */
				iterator->insert_before(iterator,event);
				break;
			}
		}
		iterator->destroy(iterator);
		break;
	}

	pthread_cond_signal( &(this->condvar));
	pthread_mutex_unlock(&(this->mutex));
}

/**
 * Implements  event_queue_t.add_relative.
 */
static void add_relative(event_queue_t *this, job_t *job, u_int32_t ms)
{
	timeval_t current_time;
	timeval_t time;
	
	time_t s = ms / 1000;
	suseconds_t us = (ms - s * 1000) * 1000;
	
	gettimeofday(&current_time, NULL);
	
	time.tv_usec = (current_time.tv_usec + us) % 1000000;
	time.tv_sec = current_time.tv_sec + (current_time.tv_usec + us)/1000000 + s;
	
	this->add_absolute(this, job, time);
}


/**
 * Implements event_queue_t.destroy.
 */
static void event_queue_destroy(private_event_queue_t *this)
{
	event_t *event;
	while (this->list->remove_last(this->list, (void**)&event) == SUCCESS)
	{
		event->job->destroy(event->job);
		free(event);
	}
	this->list->destroy(this->list);
	pthread_mutex_destroy(&(this->mutex));
	pthread_cond_destroy(&(this->condvar));
	free(this);
}

/*
 * Documented in header
 */
event_queue_t *event_queue_create()
{
	private_event_queue_t *this = malloc_thing(private_event_queue_t);

	this->public.get_count = (int (*) (event_queue_t *event_queue)) get_count;
	this->public.get = (job_t *(*) (event_queue_t *event_queue)) get;
	this->public.add_absolute = (void (*) (event_queue_t *event_queue, job_t *job, timeval_t time)) add_absolute;
	this->public.add_relative = (void (*) (event_queue_t *event_queue, job_t *job, u_int32_t ms)) add_relative;
	this->public.destroy = (void (*) (event_queue_t *event_queue)) event_queue_destroy;

	this->list = linked_list_create();
	pthread_mutex_init(&(this->mutex), NULL);
	pthread_cond_init(&(this->condvar), NULL);

	return (&this->public);
}
