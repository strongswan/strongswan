/**
 * @file retransmit_request_job.c
 * 
 * @brief Implementation of retransmit_request_job_t.
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
 
#include "retransmit_request_job.h"


#include <utils/allocator.h>


typedef struct private_retransmit_request_job_t private_retransmit_request_job_t;

/**
 * Private data of an retransmit_request_job_t Object.
 */
struct private_retransmit_request_job_t {
	/**
	 * Public retransmit_request_job_t interface.
	 */
	retransmit_request_job_t public;
	
	/**
	 * Message ID of the request to resend.
	 */
	u_int32_t message_id;

	/**
	 * ID of the IKE_SA which the message belongs to.
	 */
	ike_sa_id_t *ike_sa_id;
};


/**
 * Implements job_t.get_type.
 */
static job_type_t get_type(private_retransmit_request_job_t *this)
{
	return RETRANSMIT_REQUEST;
}

/**
 * Implements retransmit_request_job_t.get_ike_sa_id.
 */
static ike_sa_id_t *get_ike_sa_id(private_retransmit_request_job_t *this)
{
	return this->ike_sa_id;
}

/**
 * Implements retransmit_request_job_t.get_message_id.
 */
static u_int32_t get_message_id(private_retransmit_request_job_t *this)
{
	return this->message_id;
}


/**
 * Implements job_t.destroy.
 */
static void destroy(private_retransmit_request_job_t *this)
{
	this->ike_sa_id->destroy(this->ike_sa_id);
	allocator_free(this);
}

/*
 * Described in header.
 */
retransmit_request_job_t *retransmit_request_job_create(u_int32_t message_id,ike_sa_id_t *ike_sa_id)
{
	private_retransmit_request_job_t *this = allocator_alloc_thing(private_retransmit_request_job_t);
	
	/* interface functions */
	this->public.job_interface.get_type = (job_type_t (*) (job_t *)) get_type;
	/* same as destroy */
	this->public.job_interface.destroy_all = (void (*) (job_t *)) destroy;
	this->public.job_interface.destroy = (void (*) (job_t *)) destroy;
	
	/* public functions */
	this->public.get_ike_sa_id = (ike_sa_id_t * (*)(retransmit_request_job_t *)) get_ike_sa_id;
	this->public.get_message_id = (u_int32_t (*)(retransmit_request_job_t *)) get_message_id;
	this->public.destroy = (void (*)(retransmit_request_job_t *)) destroy;
	
	/* private variables */
	this->message_id = message_id;
	this->ike_sa_id = ike_sa_id->clone(ike_sa_id);
	
	return &(this->public);
}
