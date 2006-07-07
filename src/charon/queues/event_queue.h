/**
 * @file event_queue.h
 *
 * @brief Interface of job_queue_t.
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

#ifndef EVENT_QUEUE_H_
#define EVENT_QUEUE_H_

#include <sys/time.h>

#include <types.h>
#include <queues/jobs/job.h>

typedef struct event_queue_t event_queue_t;

/**
 * @brief Event-Queue used to store timed events.
 * 
 * Added events are sorted. The get method blocks until
 * the time is elapsed to process the next event. The get 
 * method is called from the scheduler_t thread, which
 * will add the jobs to to job_queue_t for further processing.
 *
 * Although the event-queue is based on a linked_list_t
 * all access functions are thread-save implemented.
 * 
 * @b Constructors:
 * - event_queue_create()
 * 
 * @ingroup queues
 */
struct event_queue_t {

	/**
	 * @brief Returns number of events in queue.
	 *
	 * @param event_queue 	calling object
	 * @return 				number of events in queue
	 */
	int (*get_count) (event_queue_t *event_queue);

	/**
	 * @brief Get the next job from the event-queue.
	 *
	 * If no event is pending, this function blocks until a job can be returned.
	 *
	 * @param event_queue 	calling object
 	 * @param[out] job 		pointer to a job pointer where to job is returned to
	 * @return 				next job
	 */
	job_t *(*get) (event_queue_t *event_queue);

	/**
	 * @brief Adds a event to the queue, using a relative time.
	 *
	 * This function is non blocking and adds a job_t at a specific time to the list.
	 * The specific job object has to get destroyed by the thread which
	 * removes the job.
	 *
	 * @param event_queue 	calling object
 	 * @param[in] job 		job to add to the queue (job is not copied)
  	 * @param[in] time 		relative time, when the event has to get fired
	 */
	void (*add_relative) (event_queue_t *event_queue, job_t *job, u_int32_t ms);

	/**
	 * @brief Adds a event to the queue, using an absolute time.
	 *
	 * This function is non blocking and adds a job_t at a specific time to the list.
	 * The specific job object has to get destroyed by the thread which
	 * removes the job.
	 *
	 * @param event_queue 	calling object
 	 * @param[in] job		job to add to the queue (job is not copied)
  	 * @param[in] time		absolute time, when the event has to get fired
	 */
	void (*add_absolute) (event_queue_t *event_queue, job_t *job, timeval_t time);

	/**
	 * @brief Destroys a event_queue object.
	 *
	 * @warning The caller of this function has to make sure
	 * that no thread is going to add or get an event from the event_queue
	 * after calling this function.
	 *
	 * @param event_queue 	calling object
	 */
	void (*destroy) (event_queue_t *event_queue);
};

/**
 * @brief Creates an empty event_queue.
 *
 * @returns event_queue_t object
 * 
 * @ingroup queues
 */
event_queue_t *event_queue_create(void);
		  
#endif /*EVENT_QUEUE_H_*/
