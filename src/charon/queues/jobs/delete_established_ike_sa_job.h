/**
 * @file delete_established_ike_sa_job.h
 * 
 * @brief Interface of delete_established_ike_sa_job_t.
 * 
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
 
#ifndef DELETE_ESTABLISHED_IKE_SA_JOB_H_
#define DELETE_ESTABLISHED_IKE_SA_JOB_H_

#include <types.h>
#include <sa/ike_sa_id.h>
#include <queues/jobs/job.h>


typedef struct delete_established_ike_sa_job_t delete_established_ike_sa_job_t;

/**
 * @brief Class representing an DELETE_ESTABLISHED_IKE_SA Job.
 * 
 * This job initiates the deletion of an IKE_SA. The SA
 * to delete is specified via an ike_sa_id_t.
 * 
 * @b Constructors:
 *  - delete_established_ike_sa_job_create()
 * 
 * @ingroup jobs
 */
struct delete_established_ike_sa_job_t {
	/**
	 * The job_t interface.
	 */
	job_t job_interface;
};

/**
 * @brief Creates a job of type DELETE_ESTABLISHED_IKE_SA.
 * 
 * @param ike_sa_id		id of the IKE_SA to delete
 * @return				delete_established_ike_sa_job_t object
 * 
 * @ingroup jobs
 */
delete_established_ike_sa_job_t *delete_established_ike_sa_job_create(ike_sa_id_t *ike_sa_id);

#endif /*DELETE_ESTABLISHED_IKE_SA_JOB_H_*/
