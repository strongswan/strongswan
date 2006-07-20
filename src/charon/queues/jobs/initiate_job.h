/**
 * @file initiate_job.h
 * 
 * @brief Interface of initiate_job_t.
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

#ifndef INITIATE_IKE_SA_JOB_H_
#define INITIATE_IKE_SA_JOB_H_

#include <types.h>
#include <queues/jobs/job.h>
#include <config/connections/connection.h>
#include <config/policies/policy.h>


typedef struct initiate_job_t initiate_job_t;

/**
 * @brief Class representing an INITIATE_IKE_SA Job.
 * 
 * This job is created if an IKE_SA should be iniated.
 * 
 * @b Constructors:
 * - initiate_job_create()
 * 
 * @ingroup jobs
 */
struct initiate_job_t {
	/**
	 * implements job_t interface
	 */
	job_t job_interface;
};

/**
 * @brief Creates a job of type INITIATE_IKE_SA.
 * 
 * @param connection	connection_t to initialize
 * @param policy		policy to set up
 * @return				initiate_job_t object
 * 
 * @ingroup jobs
 */
initiate_job_t *initiate_job_create(connection_t *connection,
												  policy_t *policy);

#endif /*INITIATE_IKE_SA_JOB_H_*/
