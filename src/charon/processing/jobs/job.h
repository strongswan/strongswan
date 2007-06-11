/**
 * @file job.h
 * 
 * @brief Interface job_t.
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

#ifndef JOB_H_
#define JOB_H_

typedef struct job_t job_t;

#include <library.h>


/**
 * @brief Job-Interface as it is stored in the job queue.
 * 
 * @b Constructors:
 * - None, use specific implementation of the interface.
 * 
 * @ingroup jobs
 */
struct job_t {

	/**
	 * @brief Execute a job.
	 * 
	 * The processing facility executes a job using this method. Jobs are
	 * one-shot, they destroy themself after execution, so don't use a job
	 * once it has been executed.
	 *
	 * @param this 				calling object
	 */
	void (*execute) (job_t *this);

	/**
	 * @brief Destroy a job.
	 *
	 * Is only called whenever a job was not executed (e.g. due daemon shutdown).
	 * After execution, jobs destroy themself.
	 * 
	 * @param job_t calling object
	 */
	void (*destroy) (job_t *job);
};

#endif /* JOB_H_ */

