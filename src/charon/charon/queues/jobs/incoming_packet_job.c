/**
 * @file incoming_packet_job.h
 * 
 * @brief Implementation of incoming_packet_job_t.
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


#include "incoming_packet_job.h"



typedef struct private_incoming_packet_job_t private_incoming_packet_job_t;

/**
 * Private data of an incoming_packet_job_t Object
 */
struct private_incoming_packet_job_t {
	/**
	 * public incoming_packet_job_t interface
	 */
	incoming_packet_job_t public;
	
	/**
	 * Assigned packet
	 */
	packet_t *packet;
};

/**
 * Implements job_t.get_type.
 */
static job_type_t get_type(private_incoming_packet_job_t *this)
{
	return INCOMING_PACKET;
}

/**
 * Implements incoming_packet_job_t.get_packet.
 */
static packet_t *get_packet(private_incoming_packet_job_t *this)
{
	return this->packet;
}

/**
 * Implements job_t.destroy_all.
 */
static void destroy_all(private_incoming_packet_job_t *this)
{
	if (this->packet != NULL)
	{
		this->packet->destroy(this->packet);
	}
	free(this);
}

/**
 * Implements job_t.destroy.
 */
static void destroy(job_t *job)
{
	private_incoming_packet_job_t *this = (private_incoming_packet_job_t *) job;
	free(this);
}

/*
 * Described in header
 */
incoming_packet_job_t *incoming_packet_job_create(packet_t *packet)
{
	private_incoming_packet_job_t *this = malloc_thing(private_incoming_packet_job_t);

	/* interface functions */
	this->public.job_interface.get_type = (job_type_t (*) (job_t *)) get_type;
	this->public.job_interface.destroy_all = (void (*) (job_t *)) destroy_all;
	this->public.job_interface.destroy = destroy;
	
	/* public functions */
	this->public.get_packet = (packet_t * (*)(incoming_packet_job_t *)) get_packet;
	this->public.destroy = (void (*)(incoming_packet_job_t *)) destroy;
	
	/* private variables */
	this->packet = packet;
	
	return &(this->public);
}
