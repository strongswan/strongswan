/**
 * @file incoming_packet_job.h
 * 
 * @brief Interface of incoming_packet_job_t.
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

#ifndef INCOMING_PACKET_JOB_H_
#define INCOMING_PACKET_JOB_H_

#include <types.h>
#include <network/packet.h>
#include <queues/jobs/job.h>


typedef struct incoming_packet_job_t incoming_packet_job_t;

/**
 * @brief Class representing an INCOMING_PACKET Job.
 * 
 * An incoming pack job is created from the receiver, which has
 * read a packet to process from the socket.
 * 
 * @b Constructors:
 * - incoming_packet_job_create()
 * 
 * @ingroup jobs
 */
struct incoming_packet_job_t {
	/**
	 * implements job_t interface
	 */
	job_t job_interface;
	
	/**
	 * @brief Get associated packet.
	 * 
	 * @param this	calling object
	 * @return		associated packet
	 */
	packet_t *(*get_packet)(incoming_packet_job_t *this);
};

/**
 * @brief Creates a job of type INCOMING_PACKET
 * 
 * @param[in] packet		packet to assign with this job
 * @return					created incoming_packet_job_t object
 * 
 * @ingroup jobs
 */
incoming_packet_job_t *incoming_packet_job_create(packet_t *packet);

#endif /*INCOMING_PACKET_JOB_H_*/
