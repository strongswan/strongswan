/*
 * Copyright (C) 2012 Tobias Brunner
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
typedef enum job_requeue_t job_requeue_t;
typedef enum job_status_t job_status_t;

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
 * Job requeueing policy.
 *
 * The job requeueing policy defines how a job is handled after it has been
 * executed.
 */
enum job_requeue_t {
	/** Do not requeue job, destroy it */
	JOB_REQUEUE_NONE = 0,
	/** Requeue the job fairly, i.e. it is inserted at the end of the queue */
	JOB_REQUEUE_FAIR,
	/** Reexecute the job directly, without the need of requeueing it */
	JOB_REQUEUE_DIRECT,
	/** For jobs that rescheduled themselves via scheduler_t */
	JOB_REQUEUE_SCHEDULED,
};

/**
 * Job status
 */
enum job_status_t {
	/** The job is queued and has not yet been executed */
	JOB_STATUS_QUEUED = 0,
	/** During execution */
	JOB_STATUS_EXECUTING,
	/** If the job got canceled */
	JOB_STATUS_CANCELED,
	/** The job was executed successfully */
	JOB_STATUS_DONE,
};

/**
 * Job interface as it is stored in the job queue.
 */
struct job_t {

	/**
	 * Status of this job, is modified exclusively by the processor/scheduler
	 */
	job_status_t status;

	/**
	 * Execute a job.
	 *
	 * The processing facility executes a job using this method. Jobs are
	 * one-shot, they are destroyed after execution (depending on the return
	 * value here), so don't use a job once it has been queued.
	 *
	 * @return			policy how to requeue the job
	 */
	job_requeue_t (*execute) (job_t *this);

	/**
	 * Get the priority of a job.
	 *
	 * @return			job priority
	 */
	job_priority_t (*get_priority)(job_t *this);

	/**
	 * Destroy a job.
	 *
	 * Is called after a job is executed or got canceled.  It is also called
	 * for queued jobs that were never executed.
	 *
	 * Use the status of a job to decide what to do during destruction.
	 */
	void (*destroy) (job_t *this);
};

#endif /** JOB_H_ @}*/
