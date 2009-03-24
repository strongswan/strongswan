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

#include <library.h>
#include <processing/jobs/job.h>

/**
 * The scheduler queues and executes timed events.
 *
 * The scheduler stores timed events and passes them to the processor.
 */
struct scheduler_t { 	

	/**
	 * Adds a event to the queue, using a relative time offset.
	 *
	 * Schedules a job for execution using a relative time offset.
	 *
 	 * @param job 			job to schedule
  	 * @param time 			relative to to schedule job (in ms)
	 */
	void (*schedule_job) (scheduler_t *this, job_t *job, u_int32_t time);
	
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
