/**
 * @file job_queue.h
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

#ifndef JOB_QUEUE_H_
#define JOB_QUEUE_H_

#include <types.h>
#include <queues/jobs/job.h>

typedef struct job_queue_t job_queue_t;

/**
 * @brief The job queue stores jobs, which will be processed by the thread_pool_t.
 *
 * Jobs are added from various sources, from the threads and 
 * from the event_queue_t.
 * Although the job-queue is based on a linked_list_t
 * all access functions are thread-save implemented.
 * 
 * @b Constructors:
 * - job_queue_create()
 * 
 * @ingroup queues
 */
struct job_queue_t {

	/**
	 * @brief Returns number of jobs in queue.
	 *
	 * @param job_queue_t 	calling object
	 * @returns 			number of items in queue
	 */
	int (*get_count) (job_queue_t *job_queue);

	/**
	 * @brief Get the next job from the queue.
	 *
	 * If the queue is empty, this function blocks until a job can be returned.
	 * After using, the returned job has to get destroyed by the caller.
	 *
	 * @param job_queue_t 	calling object
 	 * @param[out] job 		pointer to a job pointer where to job is returned to
	 * @return				next job
	 */
	job_t *(*get) (job_queue_t *job_queue);

	/**
	 * @brief Adds a job to the queue.
	 *
	 * This function is non blocking and adds a job_t to the list.
	 * The specific job object has to get destroyed by the thread which
	 * removes the job.
	 *
	 * @param job_queue_t 	calling object
 	 * @param job 			job to add to the queue (job is not copied)
	 */
	void (*add) (job_queue_t *job_queue, job_t *job);

	/**
	 * @brief Destroys a job_queue object.
	 *
	 * @warning The caller of this function has to make sure
	 * that no thread is going to add or get a job from the job_queue
	 * after calling this function.
	 *
	 * @param job_queue_t 	calling object
	 */
	void (*destroy) (job_queue_t *job_queue);
};

/**
 * @brief Creates an empty job_queue.
 *
 * @return job_queue_t object
 * 
 * @ingroup queues
 */
job_queue_t *job_queue_create(void);

#endif /*JOB_QUEUE_H_*/
