/**
 * @file incoming_packet_job.h
 * 
 * @brief Implementation of incoming_packet_job_t.
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


#include "incoming_packet_job.h"

#include <daemon.h>

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
 * send a notify back to the sender
 */
static void send_notify_response(private_incoming_packet_job_t *this,
								 message_t *request,
								 notify_type_t type)
{
	notify_payload_t *notify;
	message_t *response;
	host_t *src, *dst;
	packet_t *packet;
	ike_sa_id_t *ike_sa_id;
	
	ike_sa_id = request->get_ike_sa_id(request);
	ike_sa_id = ike_sa_id->clone(ike_sa_id);
	ike_sa_id->switch_initiator(ike_sa_id);
	
	response = message_create();
	dst = request->get_source(request);
	src = request->get_destination(request);
	response->set_source(response, src->clone(src));
	response->set_destination(response, dst->clone(dst));
	response->set_exchange_type(response, request->get_exchange_type(request));
	response->set_request(response, FALSE);
	response->set_message_id(response, 0);
	response->set_ike_sa_id(response, ike_sa_id);
	ike_sa_id->destroy(ike_sa_id);
	notify = notify_payload_create_from_protocol_and_type(PROTO_NONE, type);
	response->add_payload(response, (payload_t *)notify);
	/* generation may fail, as most messages need a crypter/signer.
	 * TODO: Use transforms implementing the "NULL" algorithm */
	if (response->generate(response, NULL, NULL, &packet) != SUCCESS)
	{
		response->destroy(response);
		return;
	}
	this->logger->log(this->logger, CONTROL, "sending %s notify",
					  mapping_find(notify_type_m, type)); 
	charon->send_queue->add(charon->send_queue, packet);
	response->destroy(response);
	return;
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
	host_t *src, *dst;
	
	message = message_create_from_packet(this->packet->clone(this->packet));
	src = message->get_source(message);
	dst = message->get_destination(message);
	this->logger->log(this->logger, CONTROL, "received packet: from %s[%d] to %s[%d]",
					  src->get_string(src), src->get_port(src),
					  dst->get_string(dst), dst->get_port(dst));
	
	status = message->parse_header(message);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "received message with invalid IKE header, ignored");
		message->destroy(message);
		return DESTROY_ME;
	}
	
	if ((message->get_major_version(message) != IKE_MAJOR_VERSION) ||
		(message->get_minor_version(message) != IKE_MINOR_VERSION))
	{
		this->logger->log(this->logger, ERROR,
						  "received a packet with IKE version %d.%d, not supported",
						  message->get_major_version(message),
						  message->get_minor_version(message));
		if ((message->get_exchange_type(message) == IKE_SA_INIT) && (message->get_request(message)))
		{
			send_notify_response(this, message, INVALID_MAJOR_VERSION);
		}
		message->destroy(message);
		return DESTROY_ME;
	}
	
	ike_sa_id = message->get_ike_sa_id(message);
	ike_sa_id = ike_sa_id->clone(ike_sa_id);
	ike_sa_id->switch_initiator(ike_sa_id);
	ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, ike_sa_id);
	if (ike_sa == NULL)
	{
		this->logger->log(this->logger, ERROR,
						  "received packet with SPIs %llx:%llx, but no such IKE_SA",
						  ike_sa_id->get_initiator_spi(ike_sa_id),
						  ike_sa_id->get_responder_spi(ike_sa_id));
		if (message->get_request(message))
		{
			/* TODO: send notify if we have NULL crypters, 
			 * see todo in send_notify_response 
			send_notify_response(this, message, INVALID_IKE_SPI); */
		}
		ike_sa_id->destroy(ike_sa_id);	
		message->destroy(message);
		return DESTROY_ME;
	}
	
	status = ike_sa->process_message(ike_sa, message);
	if (status == DESTROY_ME)
	{
		charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
	}
	else
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	}
	ike_sa_id->destroy(ike_sa_id);
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
