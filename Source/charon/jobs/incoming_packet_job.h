/**
 * @file incoming_packet_job.h
 * 
 * @brief Job of type INCOMING_PACKET
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

#ifndef INCOMING_PACKET_JOB_H_
#define INCOMING_PACKET_JOB_H_

#include "job.h"
#include "../types.h"
#include "../packet.h"

/**
 * Object representing an INCOMING_PACKET Job
 * 
 */
typedef struct incoming_packet_job_s incoming_packet_job_t;

struct incoming_packet_job_s {
	/**
	 * implements job_t interface
	 */
	job_t job_interface;
	
	/**
	 * @brief Returns the assigned packet_t object
	 * 	
	 * @warning Returned packet is not cloned and has to get destroyed by the caller
	 * 
	 * @param this 			calling incoming_packet_job_t object
	 * @param[out] packet 	assigned packet will be written into this location
	 * @return 				SUCCESS
	 */
	status_t (*get_packet) (incoming_packet_job_t *this, packet_t **packet);

	/**
	 * @brief Destroys an incoming_packet_job_t object.
	 *
	 * @param this 	incoming_packet_job_t object to destroy
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*destroy) (incoming_packet_job_t *this);
};

/**
 * Creates a job of type INCOMING_PACKET
 * 
 * @param[in] packet		packet to assign with this job
 * @return
 * 						- incoming_packet_job_t if successfully
 * 						- NULL if out of ressources
 */
incoming_packet_job_t *incoming_packet_job_create(packet_t *packet);


#endif /*INCOMING_PACKET_JOB_H_*/
