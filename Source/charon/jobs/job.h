/**
 * @file job.h
 * 
 * @brief Job-Interface representing a job e.g. in job_queue
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

#ifndef JOB_H_
#define JOB_H_

#include "../types.h"
#include "../definitions.h"

/**
 * Type of Jobs in Job-Queue
 */
typedef enum job_type_e job_type_t;

enum job_type_e {
	/** 
	 * Process an incoming IKEv2-Message
	 * 
 	 * Job is implemented in class type incoming_packet_job_t
	 */
	INCOMING_PACKET,
	/** 
	 * Retransmit an IKEv2-Message
	 */
	RETRANSMIT_REQUEST,
	/** 
	 * Establish an ike sa as initiator
	 * 
	 * Job is implemented in class type initiate_ike_sa_job_t
	 */
	INITIATE_IKE_SA,
	/** 
	 * Delete an ike sa
	 * 
	 * Job is implemented in class type delete_ike_sa_job_t
	 */
	DELETE_IKE_SA
	
	
	/* more job types have to be inserted here */
};

extern mapping_t job_type_m[];

/**
 * @brief Job-Interface as it is stored in the job queue
 * 
 * A job consists of a job-type and one or more assigned values
 */
typedef struct job_s job_t;

struct job_s{

	/**
	 * @brief get type of job
	 *
	 * @param this 				calling object
	 * @return 					type of this job
	 */
	job_type_t (*get_type) (job_t *this);

	/**
	 * @brief Destroys a job_t object and all assigned data!
	 * 
	 * @param job_t calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy_all) (job_t *job);

	/**
	 * @brief Destroys a job_t object
	 * 
	 * @param job_t calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (job_t *job);
};

#include "initiate_ike_sa_job.h"
#include "delete_ike_sa_job.h"
#include "incoming_packet_job.h"



#endif /*JOB_H_*/
