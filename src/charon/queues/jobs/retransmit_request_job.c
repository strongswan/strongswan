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

#include <daemon.h>

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
	
	/**
	 * Number of times a request was retransmitted
	 */
	u_int32_t retransmit_count;
	
	/**
	 * Logger reference
	 */
	logger_t *logger;
};

/**
 * Implements job_t.get_type.
 */
static job_type_t get_type(private_retransmit_request_job_t *this)
{
	return RETRANSMIT_REQUEST;
}

/**
 * Implementation of job_t.execute.
 */
static status_t execute(private_retransmit_request_job_t *this)
{
	bool stop_retransmitting = FALSE;
	u_int32_t timeout;
	ike_sa_t *ike_sa;
	status_t status;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Checking out IKE SA %lld:%lld, role %s", 
					  this->ike_sa_id->get_initiator_spi(this->ike_sa_id),
					  this->ike_sa_id->get_responder_spi(this->ike_sa_id),
					  this->ike_sa_id->is_initiator(this->ike_sa_id) ? "initiator" : "responder");
				
	status = charon->ike_sa_manager->checkout(charon->ike_sa_manager, this->ike_sa_id, &ike_sa);
	if ((status != SUCCESS) && (status != CREATED))
	{
		this->logger->log(this->logger, ERROR|LEVEL1, 
						  "IKE SA could not be checked out. Already deleted?");
		return DESTROY_ME;
	}
	
	status = ike_sa->retransmit_request(ike_sa, this->message_id);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, CONTROL|LEVEL3, 
								 "Message doesn't have to be retransmitted");
		stop_retransmitting = TRUE;
	}
				
	this->logger->log(this->logger, CONTROL|LEVEL2, "Checkin IKE SA %lld:%lld, role %s", 
					  this->ike_sa_id->get_initiator_spi(this->ike_sa_id),
					  this->ike_sa_id->get_responder_spi(this->ike_sa_id),
					  this->ike_sa_id->is_initiator(this->ike_sa_id) ? "initiator" : "responder");

	status = charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Checkin of IKE SA failed!");
	}

	if (stop_retransmitting)
	{
		return DESTROY_ME;
	}
	
	this->retransmit_count++;
	status = charon->configuration->get_retransmit_timeout(charon->configuration,
			this->retransmit_count, &timeout);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, CONTROL|LEVEL2, "Message will not be retransmitted anymore");
		return DESTROY_ME;
	}
	charon->event_queue->add_relative(charon->event_queue, (job_t *)this, timeout);
	return SUCCESS;
}

/**
 * Implements job_t.destroy.
 */
static void destroy(private_retransmit_request_job_t *this)
{
	this->ike_sa_id->destroy(this->ike_sa_id);
	free(this);
}

/*
 * Described in header.
 */
retransmit_request_job_t *retransmit_request_job_create(u_int32_t message_id,ike_sa_id_t *ike_sa_id)
{
	private_retransmit_request_job_t *this = malloc_thing(private_retransmit_request_job_t);
	
	/* interface functions */
	this->public.job_interface.get_type = (job_type_t (*) (job_t *)) get_type;
	this->public.job_interface.execute = (status_t (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void (*) (job_t *)) destroy;

	/* private variables */
	this->message_id = message_id;
	this->retransmit_count = 0;
	this->ike_sa_id = ike_sa_id->clone(ike_sa_id);
	this->logger = logger_manager->get_logger(logger_manager, WORKER);
	
	return &(this->public);
}
