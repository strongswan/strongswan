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

/**
 * @defgroup job job
 * @{ @ingroup jobs
 */

#ifndef JOB_H_
#define JOB_H_

typedef struct job_t job_t;
typedef enum job_priority_t job_priority_t;

#include <library.h>

/**
 * Priority classes of jobs
 */
enum job_priority_t {
	/** Critical infrastructure jobs that should always been served */
	JOB_PRIO_CRITICAL = 0,
	/** Short jobs executed with highest priority */
	JOB_PRIO_HIGH,
	/** Default job priority */
	JOB_PRIO_MEDIUM,
	/** Low priority jobs with thread blocking operations */
	JOB_PRIO_LOW,
	JOB_PRIO_MAX
};

/**
 * Enum names for job priorities
 */
extern enum_name_t *job_priority_names;

/**
 * Job interface as it is stored in the job queue.
 */
struct job_t {

	/**
	 * Execute a job.
	 *
	 * The processing facility executes a job using this method. Jobs are
	 * one-shot, they destroy themself after execution, so don't use a job
	 * once it has been executed.
	 */
	void (*execute) (job_t *this);

	/**
	 * Get the priority of a job.
	 *
	 * @return			job priority
	 */
	job_priority_t (*get_priority)(job_t *this);

	/**
	 * Destroy a job.
	 *
	 * Is only called whenever a job was not executed (e.g. due daemon shutdown).
	 * After execution, jobs destroy themself.
	 */
	void (*destroy) (job_t *this);
};

#endif /** JOB_H_ @}*/
