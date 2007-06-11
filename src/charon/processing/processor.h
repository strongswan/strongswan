/**
 * @file processor.h
 * 
 * @brief Interface of processor_t.
 * 
 */

/*
 * Copyright (C) 2005-2007 Martin Willi
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

#ifndef PROCESSOR_H_
#define PROCESSOR_H_

typedef struct processor_t processor_t;

#include <stdlib.h>

#include <library.h>
#include <processing/jobs/job.h>

/**
 * @brief The processor uses threads to process queued jobs.
 *
 * @b Constructors:
 *  - processor_create()
 * 
 * @ingroup processing
 */
struct processor_t {
	
	/**
	 * @brief Get the total number of threads used by the processor.
	 *
	 * @param this			calling object		
	 * @return				size of thread pool
	 */
	u_int (*get_total_threads) (processor_t *this);
	
	/**
	 * @brief Get the number of threads currently waiting.
	 *
	 * @param this			calling object		
	 * @return				number of idle threads
	 */
	u_int (*get_idle_threads) (processor_t *this);
	
	/**
	 * @brief Get the number of queued jobs.
	 *
	 * @param this			calling object
	 * @returns 			number of items in queue
	 */
	u_int (*get_job_load) (processor_t *this);

	/**
	 * @brief Adds a job to the queue.
	 *
	 * This function is non blocking and adds a job_t to the queue.
	 *
	 * @param this		 	calling object
 	 * @param job 			job to add to the queue
	 */
	void (*queue_job) (processor_t *this, job_t *job);
	
	/**
	 * @brief Set the number of threads to use in the processor.
	 *
	 * If the number of threads is smaller than number of currently running
	 * threads, thread count is decreased. Use 0 to disable the processor.
	 * This call blocks if it decreases thread count until threads have
	 * terminated, so make sure there are not too many blocking jobs.
	 *
	 * @param this			calling object
	 * @param count			number of threads to allocate
	 */
	void (*set_threads)(processor_t *this, u_int count);
	
	/**
	 * @brief Destroy a processor object.
	 * 
	 * @param processor	calling object
	 */
	void (*destroy) (processor_t *processor);
};

/**
 * @brief Create the thread pool without any threads.
 * 
 * @return					processor_t object
 *
 * @ingroup processing
 */
processor_t *processor_create();

#endif /*PROCESSOR_H_*/

