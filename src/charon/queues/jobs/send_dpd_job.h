/**
 * @file send_dpd_job.h
 * 
 * @brief Interface of send_dpd_job_t.
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
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

#ifndef SEND_DPD_JOB_H_
#define SEND_DPD_JOB_H_

#include <types.h>
#include <queues/jobs/job.h>
#include <config/connections/connection.h>
#include <sa/ike_sa_id.h>


typedef struct send_dpd_job_t send_dpd_job_t;

/**
 * @brief Class representing a SEND_DPD Job.
 * 
 * Job to periodically send a Dead Peer Detection (DPD) request,
 * ie. an IKE request with no payloads other than the encrypted payload
 * required by the syntax.
 * 
 * @b Constructors:
 * - send_dpd_job_create()
 * 
 * @ingroup jobs
 */
struct send_dpd_job_t {
	/**
	 * implements job_t interface
	 */
	job_t job_interface;
	
	/**
	 * @brief Destroys an send_dpd_job_t object.
	 *
	 * @param this 	send_dpd_job_t object to destroy
	 */
	void (*destroy) (send_dpd_job_t *this);
};

/**
 * @brief Creates a job of type SEND_DPD.
 * 
 * @param ike_sa_id		identification of the ike_sa as ike_sa_id_t object (gets cloned)
 * @return				initiate_ike_sa_job_t object
 * 
 * @ingroup jobs
 */
send_dpd_job_t *send_dpd_job_create(ike_sa_id_t *ike_sa_id);

#endif /*SEND_DPD_JOB_H_*/
