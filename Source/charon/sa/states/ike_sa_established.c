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

#include <utils/allocator.h>
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
	
	/**
	 * Process a notify payload
	 * 
	 * @param this				calling object
	 * @param notify_payload	notify payload
	 * @param response			response message of type INFORMATIONAL
	 *
	 * 						- SUCCESS
	 * 						- FAILED
	 * 						- DELETE_ME
	 */
	status_t (*process_notify_payload) (private_ike_sa_established_t *this, notify_payload_t *notify_payload,message_t *response);
};

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
	
	if (message->get_exchange_type(message) != INFORMATIONAL)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "Message of type %s not supported in state ike_sa_established",
							mapping_find(exchange_type_m,message->get_exchange_type(message)));
		return FAILED;
	}
	
	if (!message->get_request(message))
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "INFORMATIONAL responses not handled in state ike_sa_established");
		return FAILED;
	}
	
	ike_sa_id = this->ike_sa->public.get_id(&(this->ike_sa->public));
	
	/* get signer for verification and crypter for decryption */
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
		this->logger->log(this->logger, AUDIT, "INFORMATIONAL request decryption failed. Ignoring message");
		return status;
	}
	
	/* build empty INFORMATIONAL message */
	this->ike_sa->build_message(this->ike_sa, INFORMATIONAL, FALSE, &response);
	
	payloads = message->get_payload_iterator(message);
	
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		
		switch (payload->get_type(payload))
		{
			case NOTIFY:
			{
				notify_payload_t *notify_payload = (notify_payload_t *) payload;
				/* handle the notify directly, abort if no further processing required */
				status = this->process_notify_payload(this, notify_payload,response);
				if (status != SUCCESS)
				{
					payloads->destroy(payloads);
					response->destroy(response);
					return status;
				}
			}
			case DELETE:
			{
				delete_request = (delete_payload_t *) payload;
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR|LEVEL1, "Ignoring Payload %s (%d)", 
									mapping_find(payload_type_m, payload->get_type(payload)), payload->get_type(payload));
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
			this->logger->log(this->logger, AUDIT, "DELETE request for IKE_SA received");
			response->destroy(response);
			return DELETE_ME;
		}
		else
		{
			this->logger->log(this->logger, AUDIT, "DELETE request for CHILD_SA received. Ignored");
			response->destroy(response);
			return SUCCESS;
		}
	}
	
	status = this->ike_sa->send_response(this->ike_sa, response);
	/* message can now be sent (must not be destroyed) */
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "Unable to send INFORMATIONAL reply");
		response->destroy(response);
		return FAILED;
	}
	
	return SUCCESS;
}

/**
 * Implementation of private_ike_sa_established_t.process_notify_payload;
 */
static status_t process_notify_payload (private_ike_sa_established_t *this, notify_payload_t *notify_payload, message_t *response)
{
	notify_message_type_t notify_message_type = notify_payload->get_notify_message_type(notify_payload);
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "Process notify type %s for protocol %s",
					  mapping_find(notify_message_type_m, notify_message_type),
					  mapping_find(protocol_id_m, notify_payload->get_protocol_id(notify_payload)));
					  
	switch (notify_message_type)
	{
		default:
		{
			this->logger->log(this->logger, AUDIT, "INFORMATIONAL request contained an unknown notify (%d), ignored.", notify_message_type);
		}
	}


	return SUCCESS;	
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
	allocator_free(this);
}

/* 
 * Described in header.
 */
ike_sa_established_t *ike_sa_established_create(protected_ike_sa_t *ike_sa)
{
	private_ike_sa_established_t *this = allocator_alloc_thing(private_ike_sa_established_t);

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private functions */
	this->process_notify_payload = process_notify_payload;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = ike_sa->get_logger(ike_sa);
	
	return &(this->public);
}
