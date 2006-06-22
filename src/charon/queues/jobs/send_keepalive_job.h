/**
 * @file send_keepalive_job.h
 * 
 * @brief Interface of send_keepalive_job_t.
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

#ifndef SEND_KEEPALIVE_JOB_H_
#define SEND_KEEPALIVE_JOB_H_

#include <types.h>
#include <queues/jobs/job.h>
#include <config/connections/connection.h>
#include <sa/ike_sa_id.h>


typedef struct send_keepalive_job_t send_keepalive_job_t;

/**
 * @brief Class representing a SEND_KEEPALIVE Job.
 * 
 * This job will send a NAT keepalive packet if the IKE SA is still alive,
 * and reinsert itself into the event queue.
 * 
 * @b Constructors:
 * - send_keepalive_job_create()
 * 
 * @ingroup jobs
 */
struct send_keepalive_job_t {
	/**
	 * implements job_t interface
	 */
	job_t job_interface;
	
	/**
	 * @brief Destroys an send_keepalive_job_t object.
	 *
	 * @param this 	send_keepalive_job_t object to destroy
	 */
	void (*destroy) (send_keepalive_job_t *this);
};

/**
 * @brief Creates a job of type SEND_KEEPALIVE.
 * 
 * @param ike_sa_id		identification of the ike_sa as ike_sa_id_t object (gets cloned)
 * @return				initiate_ike_sa_job_t object
 * 
 * @ingroup jobs
 */
send_keepalive_job_t *send_keepalive_job_create(ike_sa_id_t *ike_sa_id);

#endif /*SEND_KEEPALIVE_JOB_H_*/
