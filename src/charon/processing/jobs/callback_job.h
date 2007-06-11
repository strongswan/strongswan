/**
 * @file callback_job.h
 * 
 * @brief Interface of callback_job_t.
 * 
 */

/*
 * Copyright (C) 2007 Martin Willi
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

#ifndef CALLBACK_JOB_H_
#define CALLBACK_JOB_H_

typedef struct callback_job_t callback_job_t;

#include <library.h>
#include <processing/jobs/job.h>


typedef enum job_requeue_t job_requeue_t;

/**
 * @brief Job requeueing policy
 */
enum job_requeue_t {

	/**
	 * Do not requeue job, destroy it
	 */
	JOB_REQUEUE_NONE,
	
	/**
	 * Reque the job farly, meaning it has to queue as any other job
	 */
	JOB_REQUEUE_FAIR,
	
	/**
	 * Reexecute the job directly, without the need of requeing it
	 */
	JOB_REQUEUE_DIRECT,
};

/**
 * @brief The callback function to use for the callback job.
 *
 * This is the function to use as callback for a callback job. It receives
 * a parameter supplied to the callback jobs constructor.
 *
 * @param data			param supplied to job
 * @return				requeing policy how to requeue the job
 */
typedef job_requeue_t (*callback_job_cb_t)(void *data);

/**
 * @brief Cleanup function to use for data cleanup.
 *
 * The callback has an optional user argument which receives data. However,
 * this data may be cleaned up if it is allocated. This is the function
 * to supply to the constructor.
 *
 * @param data			param supplied to job
 * @return				requeing policy how to requeue the job
 */
typedef void (*callback_job_cleanup_t)(void *data);

/**
 * @brief Class representing an callback Job.
 *
 * This is a special job which allows a simple callback function to
 * be executed by a thread of the thread pool. This allows simple execution
 * of asynchronous methods, without to manage threads.
 *
 * @b Constructors:
 * - callback_job_create()
 *
 * @ingroup jobs
 */
struct callback_job_t {
	/**
	 * The job_t interface.
	 */
	job_t job_interface;
	
	/**
	 * @brief Cancel the jobs thread and wait for its termination.
	 *
	 * @param this		calling object
	 */
	void (*cancel)(callback_job_t *this);
};

/**
 * @brief Creates a callback job.
 *
 * The cleanup function is called when the job gets destroyed to destroy
 * the associated data.
 * If parent is not NULL, the specified job gets an association. Whenever
 * the parent gets cancelled (or runs out), all of its children are cancelled,
 * too.
 * 
 * @param cb				callback to call from the processor
 * @param data				user data to supply to callback
 * @param cleanup			destructor for data on destruction, or NULL
 * @param parent			parent of this job
 * @return					callback_job_t object
 * 
 * @ingroup jobs
 */
callback_job_t *callback_job_create(callback_job_cb_t cb, void *data,
									callback_job_cleanup_t cleanup,
									callback_job_t *parent);

#endif /* CALLBACK_JOB_H_ */

