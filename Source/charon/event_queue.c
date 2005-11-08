/**
 * @file event_queue.c
 * 
 * @brief Event-Queue based on linked_list_t
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

#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>
#include <pthread.h>
#include <stdlib.h>
 
 
#include "types.h"
#include "event_queue.h"
#include "linked_list.h"



/**
 * @brief represents an event as it is stored in the event queue
 * 
 * A event consists of a event time and an assigned job object
 * 
 */
typedef struct event_s event_t;

struct event_s{
	/**
	 * Time to fire the event
	 */
	timeval_t time;

	/**
	 * Every event has its assigned job
	 */
	job_t * job;

	/**
	 * @brief Destroys a event_t object
	 * 
	 * @param event_t calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (event_t *event);
};

 
/**
 * @brief implements function destroy of event_t
 */
static status_t event_destroy(event_t *event)
{
	if (event == NULL)
	{
		return FAILED;
	}
	pfree(event);
	return SUCCESS;
}

/**
 * @brief Creates a event for a specific time
 *
 * @param time to fire the event
 * @param job job to add to job-queue at specific time
 * 
 * @return event_t event object
 */
static event_t *event_create(timeval_t time, job_t *job)
{
	event_t *this = alloc_thing(event_t, "event_t");

	this->destroy = event_destroy;

	this->time = time;
	this->job = job;
	
	return this;
}


/**
 * @brief Private Variables and Functions of event_queue class
 * 
 */
typedef struct private_event_queue_s private_event_queue_t;
 

struct private_event_queue_s {
 	event_queue_t public;
 	
	/**
	 * The events are stored in a linked list
	 */
	linked_list_t *list;
	
	/**
	 * access to linked_list is locked through this mutex
	 */
	pthread_mutex_t mutex;
	
	/**
	 * If the queue is empty or an event has not to be fired
	 * a thread has to wait
	 * This condvar is used to wake up such a thread
	 */
	pthread_cond_t condvar;	
};

/**
 * Returns the difference of to timeval structs in microseconds
 * 
 * @param end_time end time
 * @param start_time start time
 * 
 * @warning this function is also defined in the tester class
 * 			In later improvements, this function can be added to a general
 *          class type!
 * 
 * @return difference in microseconds
 */
static long time_difference(struct timeval *end_time, struct timeval *start_time)
{
	long seconds, microseconds;
	
	seconds = (end_time->tv_sec - start_time->tv_sec);
	microseconds = (end_time->tv_usec - start_time->tv_usec);
	return ((seconds * 1000000) + microseconds);
}


/**
 * @brief implements function get_count of event_queue_t
 */
static status_t get_count (private_event_queue_t *this, int *count)
{
	pthread_mutex_lock(&(this->mutex));
	status_t status = this->list->get_count(this->list,count);
	pthread_mutex_unlock(&(this->mutex));
	return status;
}

/**
 * @brief implements function get of event_queue_t
 */
static status_t get(private_event_queue_t *this, job_t **job)
{
	timespec_t timeout;
	timeval_t current_time;
	event_t * next_event;
	int count;
	int oldstate;
		
	pthread_mutex_lock(&(this->mutex));
	
	while (1)
	{
		this->list->get_count(this->list,&count);
		while(count == 0)
		{
			/* add mutex unlock handler for cancellation, enable cancellation */
			pthread_cleanup_push((void(*)(void*))pthread_mutex_unlock, (void*)&(this->mutex));
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
			
			pthread_cond_wait( &(this->condvar), &(this->mutex));
					
			/* reset cancellation, remove mutex-unlock handler (without executing) */
			pthread_setcancelstate(oldstate, NULL);
			pthread_cleanup_pop(0);
		
			this->list->get_count(this->list,&count);
		}
			
		this->list->get_first(this->list,(void **) &next_event);
		
		gettimeofday(&current_time,NULL);
		long difference = time_difference(&current_time,&(next_event->time));
		if (difference <= 0)
		{
			timeout.tv_sec = next_event->time.tv_sec;
            timeout.tv_nsec = next_event->time.tv_usec * 1000;

			pthread_cond_timedwait( &(this->condvar), &(this->mutex),&timeout);
		}
		else
		{
			/* event available */
			this->list->remove_first(this->list,(void **) &next_event);
			
			*job = next_event->job;
			
			next_event->destroy(next_event);
			break;
		}
	
	}
	pthread_cond_signal( &(this->condvar));
	
	pthread_mutex_unlock(&(this->mutex));
	
	return SUCCESS;
}

/**
 * @brief implements function add of event_queue_t
 */
static status_t add_absolute(private_event_queue_t *this, job_t *job, timeval_t time)
{
	event_t *event = event_create(time,job);
	event_t *current_event;
	status_t status;
	int count;
	
	if (event == NULL)
	{
		return FAILED;
	}
	pthread_mutex_lock(&(this->mutex));

	/* while just used to break out */
	while(1)
	{
		this->list->get_count(this->list,&count);
		if (count == 0)
		{
			status = this->list->insert_first(this->list,event);
			break;
		}
		
		/* check last entry */
		this->list->get_last(this->list,(void **) &current_event);

		if (time_difference(&(event->time), &(current_event->time)) >= 0)
		{
			/* my event has to be fired after the last event in list */
			status = this->list->insert_last(this->list,event);
			break;
		}
		
		/* check first entry */
		this->list->get_first(this->list,(void **) &current_event);

		if (time_difference(&(event->time), &(current_event->time)) < 0)
		{
			/* my event has to be fired before the first event in list */
			status = this->list->insert_first(this->list,event);
			break;
		}
		
		linked_list_iterator_t * iterator;
		
		status = this->list->create_iterator(this->list,&iterator,TRUE);
		if (status != SUCCESS)
		{
			break;
		}
		
		
		iterator->has_next(iterator);
		/* first element has not to be checked (already done) */		
		
		while(iterator->has_next(iterator))
		{
			status = iterator->current(iterator,(void **) &current_event);
			
			if (time_difference(&(event->time), &(current_event->time)) <= 0)
			{
				/* my event has to be fired before the current event in list */
				status = this->list->insert_before(this->list,iterator,event);				
				break;
			}
		}
		iterator->destroy(iterator);
		break;
	}

	pthread_cond_signal( &(this->condvar));
	pthread_mutex_unlock(&(this->mutex));

	if (status != SUCCESS)
	{
		event->destroy(event);
	}
	return status;		
}

/**
 * @brief implements function add of event_queue_t
 */
static status_t add_relative(event_queue_t *this, job_t *job, u_int32_t ms)
{
	timeval_t current_time;
	timeval_t time;
	int micros = ms * 1000;
	
	gettimeofday(&current_time, NULL);
	
	time.tv_usec = ((current_time.tv_usec + micros) % 1000000);
	time.tv_sec = current_time.tv_sec + ((current_time.tv_usec + micros)/ 1000000);
	
	return this->add_absolute(this, job, time);
}


/**
 * @brief implements function destroy of event_queue_t
 */
static status_t event_queue_destroy(private_event_queue_t *this)
{	
	int count;
	this->list->get_count(this->list,&count);
	while (count > 0)
	{
		event_t *event;	
		
		if (this->list->remove_first(this->list,(void *) &event) != SUCCESS)
		{
			this->list->destroy(this->list);
			break;
		}
		event->job->destroy(event->job);
		event->destroy(event);
		this->list->get_count(this->list,&count);
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
event_queue_t *event_queue_create()
{
	linked_list_t *linked_list = linked_list_create();
	if (linked_list == NULL)
	{
		return NULL;
	}
	
	private_event_queue_t *this = alloc_thing(private_event_queue_t, "private_event_queue_t");
	if (this == NULL)
	{
		linked_list->destroy(linked_list);
		return NULL;
	}
	
	this->public.get_count = (status_t (*) (event_queue_t *event_queue, int *count)) get_count;
	this->public.get = (status_t (*) (event_queue_t *event_queue, job_t **job)) get;
	this->public.add_absolute = (status_t (*) (event_queue_t *event_queue, job_t *job, timeval_t time)) add_absolute;
	this->public.add_relative = (status_t (*) (event_queue_t *event_queue, job_t *job, u_int32_t ms)) add_relative;
	this->public.destroy = (status_t (*) (event_queue_t *event_queue)) event_queue_destroy;
	
	this->list = linked_list;
	pthread_mutex_init(&(this->mutex), NULL);
	pthread_cond_init(&(this->condvar), NULL);
	
	return (&this->public);
}
