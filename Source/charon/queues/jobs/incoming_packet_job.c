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


#include "incoming_packet_job.h"

#include <utils/allocator.h>


typedef struct private_incoming_packet_job_t private_incoming_packet_job_t;

/**
 * Private data of an incoming_packet_job_t Object
 * 
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
 * Implements incoming_packet_job_t's get_type function.
 * See #incoming_packet_job_t.get_type for description.
 */
static job_type_t get_type(private_incoming_packet_job_t *this)
{
	return INCOMING_PACKET;
}

/**
 * Implements incoming_packet_job_t's get_configuration_name function.
 * See #incoming_packet_job_t.get_configuration_name for description.
 */
static status_t get_packet(private_incoming_packet_job_t *this,packet_t **packet)
{
	if (this->packet == NULL)
	{
		return FAILED;
	}
	*packet = this->packet;
	return SUCCESS;
}



/**
 * Implements job_t's and destroy_all function.
 * See #job_t.destroy_all description.
 */
static status_t destroy_all(private_incoming_packet_job_t *this)
{
	if (this->packet != NULL)
	{
		this->packet->destroy(this->packet);
	}
	allocator_free(this);
	return SUCCESS;
}

/**
 * Implements job_t's and incoming_packet_job_t's destroy function.
 * See #job_t.destroy or #incoming_packet_job_t.destroy for description.
 */
static status_t destroy(job_t *job)
{
	private_incoming_packet_job_t *this = (private_incoming_packet_job_t *) job;
	allocator_free(this);
	return SUCCESS;
}


/*
 * Described in header
 */
incoming_packet_job_t *incoming_packet_job_create(packet_t *packet)
{
	private_incoming_packet_job_t *this = allocator_alloc_thing(private_incoming_packet_job_t);
	if ((this == NULL))
	{
		return NULL;
	}
	
	/* interface functions */
	this->public.job_interface.get_type = (job_type_t (*) (job_t *)) get_type;
	this->public.job_interface.destroy_all = (status_t (*) (job_t *)) destroy_all;
	this->public.job_interface.destroy = destroy;
	
	/* public functions */
	this->public.get_packet = (status_t (*)(incoming_packet_job_t *,packet_t **)) get_packet;
	this->public.destroy = (status_t (*)(incoming_packet_job_t *)) destroy;
	
	/* private variables */
	this->packet = packet;
	
	return &(this->public);
}
