/**
 * @file rekey_ike_sa_job.h
 * 
 * @brief Interface of rekey_ike_sa_job_t.
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

#ifndef REKEY_IKE_SA_JOB_H_
#define REKEY_IKE_SA_JOB_H_

#include <types.h>
#include <sa/ike_sa_id.h>
#include <queues/jobs/job.h>


typedef struct rekey_ike_sa_job_t rekey_ike_sa_job_t;

/**
 * @brief Class representing an REKEY_IKE_SA Job.
 * 
 * This job initiates the rekeying of an IKE_SA.
 * 
 * @b Constructors:
 *  - rekey_ike_sa_job_create()
 * 
 * @ingroup jobs
 */
struct rekey_ike_sa_job_t {
	/**
	 * The job_t interface.
	 */
	job_t job_interface;
};

/**
 * @brief Creates a job of type REKEY_IKE_SA.
 *
 * @param ike_sa_id		ID of the IKE_SA to rekey
 * @return				rekey_ike_sa_job_t object
 * 
 * @ingroup jobs
 */
rekey_ike_sa_job_t *rekey_ike_sa_job_create(ike_sa_id_t *ike_sa_id);

#endif /* REKEY_IKE_SA_JOB_H_ */
