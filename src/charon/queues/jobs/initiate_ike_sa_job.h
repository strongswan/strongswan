/**
 * @file initiate_ike_sa_job.h
 * 
 * @brief Interface of initiate_ike_sa_job_t.
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

#ifndef INITIATE_IKE_SA_JOB_H_
#define INITIATE_IKE_SA_JOB_H_

#include <types.h>
#include <queues/jobs/job.h>
#include <config/connections/connection.h>


typedef struct initiate_ike_sa_job_t initiate_ike_sa_job_t;

/**
 * @brief Class representing an INITIATE_IKE_SA Job.
 * 
 * This job is created if an IKE_SA should be iniated. This 
 * happens via a user request, or via the kernel interface.
 * 
 * @b Constructors:
 * - initiate_ike_sa_job_create()
 * 
 * @ingroup jobs
 */
struct initiate_ike_sa_job_t {
	/**
	 * implements job_t interface
	 */
	job_t job_interface;
};

/**
 * @brief Creates a job of type INITIATE_IKE_SA.
 * 
 * @param connection	connection_t to initializes
 * @return				initiate_ike_sa_job_t object
 * 
 * @ingroup jobs
 */
initiate_ike_sa_job_t *initiate_ike_sa_job_create(connection_t *connection);

#endif /*INITIATE_IKE_SA_JOB_H_*/
