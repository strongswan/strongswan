/**
 * @file delete_child_sa_job.h
 * 
 * @brief Interface of delete_child_sa_job_t.
 * 
 */

/*
 * Copyright (C) 2006 Martin Willi
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
 
#ifndef DELETE_CHILD_SA_JOB_H_
#define DELETE_CHILD_SA_JOB_H_

#include <types.h>
#include <sa/ike_sa_id.h>
#include <queues/jobs/job.h>


typedef struct delete_child_sa_job_t delete_child_sa_job_t;

/**
 * @brief Class representing an DELETE_CHILD_SA Job.
 * 
 * This job initiates the deletion of an CHILD_SA. The SA
 * to delete is specified via the unique reqid used in kernel.
 * 
 * @b Constructors:
 *  - delete_child_sa_job_create()
 * 
 * @ingroup jobs
 */
struct delete_child_sa_job_t {
	/**
	 * The job_t interface.
	 */
	job_t job_interface;
};

/**
 * @brief Creates a job of type DELETE_CHILD_SA.
 *
 * To find the targeted CHILD_SA, the uniqe reqid used in 
 * the kernel is used.
 *
 * @param reqid		reqid CHILD_SA to rekey
 * 
 * @ingroup jobs
 */
delete_child_sa_job_t *delete_child_sa_job_create(u_int32_t reqid);

#endif /* DELETE_CHILD_SA_JOB_H_ */
