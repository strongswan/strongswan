/**
 * @file job_queue.h
 *
 * @brief Job-Queue based on linked_list_t
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

#ifndef JOB_QUEUE_H_
#define JOB_QUEUE_H_

#include "../types.h"
#include "../job.h"

/**
 * @brief Job-Queue
 *
 * Although the job-queue is based on a linked_list_t
 * all access functions are thread-save implemented
 */
typedef struct job_queue_s job_queue_t;

struct job_queue_s {

	/**
	 * @brief returns number of jobs in queue
	 *
	 * @param job_queue_t calling object
	 * @returns number of items in queue
	 */
	int (*get_count) (job_queue_t *job_queue);

	/**
	 * @brief get the next job from the queue
	 *
	 * If the queue is empty, this function blocks until a job can be returned.
	 *
	 * After using, the returned job has to get destroyed by the caller.
	 *
	 * @param job_queue_t calling object
 	 * @param[out] job pointer to a job pointer where to job is returned to
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*get) (job_queue_t *job_queue, job_t **job);

	/**
	 * @brief adds a job to the queue
	 *
	 * This function is non blocking and adds a job_t to the list.
	 * The specific job object has to get destroyed by the thread which
	 * removes the job.
	 *
	 * @param job_queue_t calling object
 	 * @param[in] job job to add to the queue (job is not copied)
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*add) (job_queue_t *job_queue, job_t *job);

	/**
	 * @brief destroys a job_queue object
	 *
	 * @warning The caller of this function has to make sure
	 * that no thread is going to add or get a job from the job_queue
	 * after calling this function.
	 *
	 * @param job_queue_t calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (job_queue_t *job_queue);
};

/**
 * @brief Creates an empty job_queue
 *
 * @return job_queue_t empty job_queue
 */
job_queue_t *job_queue_create();
#endif /*JOB_QUEUE_H_*/
