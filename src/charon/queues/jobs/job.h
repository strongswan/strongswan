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

#include <types.h>
#include <definitions.h>


typedef enum job_type_t job_type_t;

/**
 * @brief Definition of the various job types.
 * 
 * @ingroup jobs
 */
enum job_type_t {
	/** 
	 * Process an incoming IKEv2-Message.
	 * 
 	 * Job is implemented in class incoming_packet_job_t
	 */
	INCOMING_PACKET,
	
	/** 
	 * Retransmit an IKEv2-Message.
	 * 
	 * Job is implemented in class retransmit_request_job_t
	 */
	RETRANSMIT_REQUEST,
	
	/** 
	 * Set up a CHILD_SA, optional with an IKE_SA.
	 * 
	 * Job is implemented in class initiate_job_t
	 */
	INITIATE,
	
	/** 
	 * Install SPD entries.
	 * 
	 * Job is implemented in class route_job_t
	 */
	ROUTE,
	
	/** 
	 * React on a acquire message from the kernel (e.g. setup CHILD_SA)
	 * 
	 * Job is implemented in class acquire_job_t
	 */
	ACQUIRE,
	
	/** 
	 * Delete an IKE_SA.
	 * 
	 * Job is implemented in class delete_ike_sa_job_t
	 */
	DELETE_IKE_SA,
	
	/**
	 * Delete a CHILD_SA.
	 * 
	 * Job is implemented in class delete_child_sa_job_t
	 */
	DELETE_CHILD_SA,
	
	/**
	 * Rekey a CHILD_SA.
	 * 
	 * Job is implemented in class rekey_child_sa_job_t
	 */
	REKEY_CHILD_SA,
	
	/**
	 * Rekey an IKE_SA.
	 * 
	 * Job is implemented in class rekey_ike_sa_job_t
	 */
	REKEY_IKE_SA,
	
	/**
	 * Send a keepalive packet.
	 * 
	 * Job is implemented in class type send_keepalive_job_t
	 */
	SEND_KEEPALIVE,
	
	/**
	 * Send a DPD packet.
	 * 
	 * Job is implemented in class type send_dpd_job_t
	 */
	SEND_DPD
};

/**
 * string mappings for job_type_t
 * 
 * @ingroup jobs
 */
extern mapping_t job_type_m[];


typedef struct job_t job_t;

/**
 * @brief Job-Interface as it is stored in the job queue.
 * 
 * A job consists of a job-type and one or more assigned values.
 * 
 * @b Constructors:
 * - None, use specific implementation of the interface.
 * 
 * @ingroup jobs
 */
struct job_t {

	/**
	 * @brief get type of job.
	 *
	 * @param this 				calling object
	 * @return 					type of this job
	 */
	job_type_t (*get_type) (job_t *this);

	/**
	 * @brief Execute a job.
	 * 
	 * Call the internall job routine to process the
	 * job. If this method returns DESTROY_ME, the job
	 * must be destroyed by the caller.
	 *
	 * @param this 				calling object
	 * @return 					status of job execution
	 */
	status_t (*execute) (job_t *this);

	/**
	 * @brief Destroys a job_t object
	 * 
	 * @param job_t calling object
	 */
	void (*destroy) (job_t *job);
};


#endif /* JOB_H_ */
