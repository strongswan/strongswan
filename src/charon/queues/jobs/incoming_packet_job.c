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

#include <daemon.h>
#include <queues/jobs/delete_half_open_ike_sa_job.h>

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
	
	/**
	 * logger
	 */
	logger_t *logger;
};

/**
 * Implements job_t.get_type.
 */
static job_type_t get_type(private_incoming_packet_job_t *this)
{
	return INCOMING_PACKET;
}

/**
 * Implementation of job_t.execute.
 */
static status_t execute(private_incoming_packet_job_t *this)
{
	message_t *message;
	ike_sa_t *ike_sa;
	ike_sa_id_t *ike_sa_id;
	status_t status;
	packet_t *packet;
	
	message = message_create_from_packet(this->packet->clone(this->packet));
	status = message->parse_header(message);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Message header could not be verified!");
		message->destroy(message);
		return DESTROY_ME;
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Message is a %s %s", 
					  mapping_find(exchange_type_m, message->get_exchange_type(message)),
					  message->get_request(message) ? "request" : "reply");
	
	if ((message->get_major_version(message) != IKE_MAJOR_VERSION) ||
		(message->get_minor_version(message) != IKE_MINOR_VERSION))
	{
		this->logger->log(this->logger, ERROR | LEVEL2,
						  "IKE version %d.%d not supported",
						  message->get_major_version(message),
						  message->get_minor_version(message));
		if ((message->get_exchange_type(message) == IKE_SA_INIT) && (message->get_request(message)))
		{
			message_t *response;
			message->get_ike_sa_id(message, &ike_sa_id);
			ike_sa_id->switch_initiator(ike_sa_id);
			response = message_create_notify_reply(message->get_destination(message),
					message->get_source(message),
					IKE_SA_INIT, FALSE, ike_sa_id,
					INVALID_MAJOR_VERSION);
			message->destroy(message);
			ike_sa_id->destroy(ike_sa_id);
			status = response->generate(response, NULL, NULL, &packet);
			if (status != SUCCESS)
			{
				this->logger->log(this->logger, ERROR, "Could not generate packet from message");
				response->destroy(response);
				return DESTROY_ME;
			}
			this->logger->log(this->logger, ERROR, "Send notify reply of type INVALID_MAJOR_VERSION"); 
			charon->send_queue->add(charon->send_queue, packet);
			response->destroy(response);
			return DESTROY_ME;
		}
		message->destroy(message);
		return DESTROY_ME;
	}
	
	message->get_ike_sa_id(message, &ike_sa_id);
	ike_sa_id->switch_initiator(ike_sa_id);
	this->logger->log(this->logger, CONTROL|LEVEL3, "Checking out IKE SA %lld:%lld, role %s", 
					  ike_sa_id->get_initiator_spi(ike_sa_id),
					  ike_sa_id->get_responder_spi(ike_sa_id),
					  ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");
	
	status = charon->ike_sa_manager->checkout(charon->ike_sa_manager, ike_sa_id, &ike_sa);
	if ((status != SUCCESS) && (status != CREATED))
	{
		this->logger->log(this->logger, ERROR, "IKE SA could not be checked out");
		ike_sa_id->destroy(ike_sa_id);	
		message->destroy(message);
		
		/* TODO: send notify reply of type INVALID_IKE_SPI if SPI could not be found ? */
		return DESTROY_ME;
	}

	if (status == CREATED)
	{
		job_t *delete_job;
		this->logger->log(this->logger, CONTROL|LEVEL3, 
						  "Create Job to delete half open IKE_SA.");
		
		delete_job = (job_t *) delete_half_open_ike_sa_job_create(ike_sa_id);
		charon->event_queue->add_relative(charon->event_queue, delete_job, 
										  charon->configuration->get_half_open_ike_sa_timeout(charon->configuration));
	}
	
	status = ike_sa->process_message(ike_sa, message);
	
	this->logger->log(this->logger, CONTROL|LEVEL3, "%s IKE SA %lld:%lld, role %s", 
					  status == DESTROY_ME ? "Checkin and delete" : "Checkin",
					  ike_sa_id->get_initiator_spi(ike_sa_id),
					  ike_sa_id->get_responder_spi(ike_sa_id),
					  ike_sa_id->is_initiator(ike_sa_id) ? "initiator" : "responder");
	ike_sa_id->destroy(ike_sa_id);
	
	if (status == DESTROY_ME)
	{
		status = charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
	}
	else
	{
		status = charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	}
	
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Checkin of IKE SA failed!");
	}
	message->destroy(message);
	return DESTROY_ME;
}

/**
 * Implements incoming_packet_job_t.get_packet.
 */
static packet_t* get_packet(private_incoming_packet_job_t *this)
{
	return this->packet;
}

/**
 * Implements job_t.destroy.
 */
static void destroy(private_incoming_packet_job_t *this)
{
	this->packet->destroy(this->packet);
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
	this->public.job_interface.execute = (status_t (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void(*)(job_t*))destroy;
	
	this->public.get_packet = (packet_t*(*)(incoming_packet_job_t*)) get_packet;
	
	/* private variables */
	this->packet = packet;
	this->logger = logger_manager->get_logger(logger_manager, WORKER);
	
	return &(this->public);
}
