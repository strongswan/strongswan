/**
 * @file job_queue.h
 * 
 * @brief Job-Queue based on linked_list_t
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

#ifndef JOB_QUEUE_H_
#define JOB_QUEUE_H_

#include "linked_list.h"

/**
 * Type of Jobs
 */
typedef enum job_type_e job_type_t;

enum job_type_e{
	/** 
	 * Job is to process an incoming IKEv2-Message
	 */
	INCOMING_PACKET,
	/** 
	 * Job is to retransmit an IKEv2-Message
	 */
	RETRANSMIT_REQUEST,
	/** 
	 * Job is to establish an ike sa as initiator
	 */
	ESTABLISH_IKE_SA
};


/**
 * @brief Job like it is represented in the job queue
 */
typedef struct job_s job_t;


struct job_s{
	job_type_t type;
	/**
	 * Every job has its assigned_data
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

/**
 * @brief Job-Queue
 */
typedef struct job_queue_s job_queue_t;

struct job_queue_s {
	
	/**
	 * @brief Returns number of jobs in queue
	 * 
	 * @param job_queue_t calling object
 	 * @param count integer pointer to store the job count in
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*get_count) (job_queue_t *job_queue, int *count);

	/**
	 * @brief Get the next job from the queue
	 * 
	 * If the queue is empty, this function blocks until job can be returned.
	 * 
	 * After using, the returned job has to get destroyed.
	 * 
	 * @param job_queue_t calling object
 	 * @param job pointer to a job pointer where to job is returned to
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*get) (job_queue_t *job_queue, job_t **job);
	
	/**
	 * @brief Adds a job to the queue
	 * 
	 * This function is non blocking
	 * 
	 * @param job_queue_t calling object
 	 * @param job job to add to the queue (job is not copied)
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*add) (job_queue_t *job_queue, job_t *job);

	/**
	 * @brief Destroys a job_queue object
	 * 
	 * @warning Has only to be called if no other thread is accessing the queue
	 * 
	 * @param job_queue_t calling object
	 * @returns SUCCESS if succeeded, FAILED otherwise
	 */
	status_t (*destroy) (job_queue_t *job_queue);
};

/**
 * @brief Creates a job_queue
 * * 
 * @return job_queue_t empty job_queue
 */
job_queue_t *job_queue_create();
#endif /*JOB_QUEUE_H_*/
