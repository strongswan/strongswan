/**
 * @file job.h
 * 
 * @brief Job-Class representing a job e.g. in job_queue
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

#include "types.h"
#include "definitions.h"

/**
 * Type of Jobs in Job-Queue
 */
typedef enum job_type_e job_type_t;

enum job_type_e {
	/** 
	 * process an incoming IKEv2-Message
	 */
	INCOMING_PACKET,
	/** 
	 * retransmit an IKEv2-Message
	 */
	RETRANSMIT_REQUEST,
	/** 
	 * establish an ike sa as initiator
	 */
	INITIATE_IKE_SA
	/* more job types have to be inserted here */
};

extern mapping_t job_type_m[];

/**
 * @brief Job as it is stored in the job queue
 * 
 * A job consists of a job-type and an assigned value
 * 
 * The value-type for a specific job is not discussed here
 */
typedef struct job_s job_t;

struct job_s{
	/**
	 * Type of job
	 */
	job_type_t type;
	/**
	 * Every job has its assigned_data based on the job type
	 */
	void * assigned_data;

	/**
	 * @brief Destroys a job_t object
	 * 
	 * @param job_t calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (job_t *job);
};

/**
 * @brief Creates a job of specific type
 *
 * @param type type of the job
 * @param assigned_data value to assign to the job
 * 
 * @return job_t job object
 */
job_t *job_create(job_type_t type, void *assigned_data);

#endif /*JOB_H_*/
