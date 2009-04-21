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
 *
 * $Id$
 */

/**
 * @defgroup scheduler scheduler
 * @{ @ingroup processing
 */

#ifndef SCHEDULER_H_
#define SCHEDULER_H_

typedef struct scheduler_t scheduler_t;

#include <sys/time.h>

#include <library.h>
#include <processing/jobs/job.h>

/**
 * The scheduler queues and executes timed events.
 *
 * The scheduler stores timed events and passes them to the processor.
 */
struct scheduler_t {
	
	/**
	 * Adds a event to the queue, using a relative time offset in s.
	 *
	 * @param job 			job to schedule
	 * @param time 			relative time to schedule job, in s
	 */
	void (*schedule_job) (scheduler_t *this, job_t *job, u_int32_t s);
	
	/**
	 * Adds a event to the queue, using a relative time offset in ms.
	 *
	 * @param job 			job to schedule
	 * @param time 			relative time to schedule job, in ms
	 */
	void (*schedule_job_ms) (scheduler_t *this, job_t *job, u_int32_t ms);
	
	/**
	 * Adds a event to the queue, using an absolut time.
	 *
	 * @param job 			job to schedule
	 * @param time 			absolut time to schedule job
	 */
	void (*schedule_job_tv) (scheduler_t *this, job_t *job, timeval_t tv);
	
	/**
	 * Returns number of jobs scheduled.
	 *
	 * @return 				number of scheduled jobs
	 */
	u_int (*get_job_load) (scheduler_t *this);
	
	/**
	 * Destroys a scheduler object.
	 */
	void (*destroy) (scheduler_t *this);
};

/**
 * Create a scheduler.
 * 
 * @return 		scheduler_t object
 */
scheduler_t *scheduler_create(void);

#endif /** SCHEDULER_H_ @}*/
