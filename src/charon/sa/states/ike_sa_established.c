/**
 * @file ike_sa_established.c
 * 
 * @brief Implementation of ike_sa_established_t.
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
 
#include "ike_sa_established.h"

#include <daemon.h>
#include <encoding/payloads/delete_payload.h>


typedef struct private_ike_sa_established_t private_ike_sa_established_t;

/**
 * Private data of a ike_sa_established_t object.
 */
struct private_ike_sa_established_t {
	/**
	 * methods of the state_t interface
	 */
	ike_sa_established_t public;
	
	/** 
	 * Assigned IKE_SA.
	 */
	protected_ike_sa_t *ike_sa;
	
	/** 
	 * Assigned logger. Use logger of IKE_SA.
	 */
	logger_t *logger;
};

/**
 * Process an informational request
 */
static status_t process_informational(private_ike_sa_established_t *this, message_t *request, message_t *response)
{
	delete_payload_t *delete_request = NULL;
	iterator_t *payloads = request->get_payload_iterator(request);
	
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		
		switch (payload->get_type(payload))
		{
			case DELETE:
			{
				delete_request = (delete_payload_t *) payload;
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR|LEVEL1, "Ignoring Payload %s (%d)", 
								  mapping_find(payload_type_m, payload->get_type(payload)), 
								  payload->get_type(payload));
				break;
			}
		}
	}
	/* iterator can be destroyed */
	payloads->destroy(payloads);
	
	if (delete_request)
	{
		if (delete_request->get_protocol_id(delete_request) == PROTO_IKE)
		{
			this->logger->log(this->logger, CONTROL, "DELETE request for IKE_SA received");
			/* we reply with an empty informational message */
			return DESTROY_ME;
		}
		else
		{
			this->logger->log(this->logger, CONTROL, "DELETE request for CHILD_SA received. Ignored");
			response->destroy(response);
			return SUCCESS;
		}
	}
	return SUCCESS;
}

/**
 * Implements state_t.get_state
 */
static status_t process_message(private_ike_sa_established_t *this, message_t *message)
{
	delete_payload_t *delete_request = NULL;
	ike_sa_id_t *ike_sa_id;
	iterator_t *payloads;
	message_t *response;
	crypter_t *crypter;
	signer_t *signer;
	status_t status;
	
	/* only requests are allowed, responses are handled in sub-states */
	if (!message->get_request(message))
	{
		this->logger->log(this->logger, ERROR | LEVEL1, 
						  "INFORMATIONAL responses not handled in state ike_sa_established");
		return FAILED;
	}
	
	/* get signer for verification and crypter for decryption */
	ike_sa_id = this->ike_sa->public.get_id(&(this->ike_sa->public));
	if (!ike_sa_id->is_initiator(ike_sa_id))
	{
		crypter = this->ike_sa->get_crypter_initiator(this->ike_sa);
		signer = this->ike_sa->get_signer_initiator(this->ike_sa);
	}
	else
	{
		crypter = this->ike_sa->get_crypter_responder(this->ike_sa);
		signer = this->ike_sa->get_signer_responder(this->ike_sa);
	}
	
	/* parse incoming message */
	status = message->parse_body(message, crypter, signer);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "%s request decryption failed. Ignoring message",
						  mapping_find(exchange_type_m, message->get_exchange_type(message)));
		return status;
	}
	
	/* prepare a reply of the same type */
	this->ike_sa->build_message(this->ike_sa, message->get_exchange_type(message), FALSE, &response);
	
	/* handle the different message types in their functions */
	switch (message->get_exchange_type(message))
	{
		case INFORMATIONAL:
			status = process_informational(this, message, response);
			break;
		default:
			this->logger->log(this->logger, ERROR | LEVEL1, 
							  "Message of type %s currently not supported in state ike_sa_established",
							  mapping_find(exchange_type_m, message->get_exchange_type(message)));
			status = NOT_SUPPORTED;
	}
	
	/* if we get a DESTROY_ME, we respond to follow strict request/reply scheme */
	if (status == SUCCESS || status == DESTROY_ME)
	{
		if (this->ike_sa->send_response(this->ike_sa, response) != SUCCESS)
		{
			/* something is seriously wrong, kill connection */
			this->logger->log(this->logger, AUDIT, "Unable to send reply. Deleting IKE_SA");
			response->destroy(response);
			status = DESTROY_ME;
		}
		else if (status == DESTROY_ME)
		{
			/* switch to delete_requested. This is not absolutly correct, but we
			* allow the clean destruction of an SA only in this state. */
			this->ike_sa->set_new_state(this->ike_sa, (state_t*)delete_requested_create(this));
			this->public.state_interface.destroy(&(this->public.state_interface));
		}
	}
	else
	{
		response->destroy(response);
	}
	return status;
}

/**
 * Implementation of state_t.get_state.
 */
static ike_sa_state_t get_state(private_ike_sa_established_t *this)
{
	return IKE_SA_ESTABLISHED;
}

/**
 * Implementation of state_t.get_state
 */
static void destroy(private_ike_sa_established_t *this)
{
	free(this);
}

/* 
 * Described in header.
 */
ike_sa_established_t *ike_sa_established_create(protected_ike_sa_t *ike_sa)
{
	private_ike_sa_established_t *this = malloc_thing(private_ike_sa_established_t);

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);
	
	return &(this->public);
}
