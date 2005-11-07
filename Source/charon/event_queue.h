/**
 * @file event_queue.h
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

#ifndef EVENT_QUEUE_H_
#define EVENT_QUEUE_H_

#include <sys/time.h>

#include "types.h"
#include "job.h"

/**
 * @brief Event-Queue
 *
 * Although the event-queue is based on a linked_list_t 
 * all access functions are thread-save implemented
 */
typedef struct event_queue_s event_queue_t;

struct event_queue_s {
	
	/**
	 * @brief returns number of events in queue
	 * 
	 * @param event_queue calling object
 	 * @param[out] count integer pointer to store the event count in
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*get_count) (event_queue_t *event_queue, int *count);

	/**
	 * @brief get the next job from the event-queue
	 * 
	 * If no event is pending, this function blocks until a job can be returned.
	 * 
	 * @param event_queue calling object
 	 * @param[out] job pointer to a job pointer where to job is returned to
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*get) (event_queue_t *event_queue, job_t **job);
	
	/**
	 * @brief adds a event to the queue
	 * 
	 * This function is non blocking and adds a job_t at a specific time to the list.
	 * The specific job-object has to get destroyed by the thread which 
	 * removes the job.
	 * 
	 * @param event_queue calling object
 	 * @param[in] job job to add to the queue (job is not copied)
  	 * @param[in] time time, when the event has to get fired
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*add) (event_queue_t *event_queue, job_t *job, timeval_t time);

	/**
	 * @brief destroys a event_queue object
	 * 
	 * @warning The caller of this function has to make sure
	 * that no thread is going to add or get an event from the event_queue
	 * after calling this function.
	 * 
	 * @param event_queue calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (event_queue_t *event_queue);
};

/**
 * @brief Creates an empty event_queue
 * 
 * @return empty event_queue object
 */
event_queue_t *event_queue_create();
#endif /*EVENT_QUEUE_H_*/
