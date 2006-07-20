/**
 * @file delete_ike_sa.c
 *
 * @brief Implementation of the delete_ike_sa transaction.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#include "delete_ike_sa.h"

#include <daemon.h>
#include <encoding/payloads/delete_payload.h>


typedef struct private_delete_ike_sa_t private_delete_ike_sa_t;

/**
 * Private members of a delete_ike_sa_t object..
 */
struct private_delete_ike_sa_t {
	
	/**
	 * Public methods and transaction_t interface.
	 */
	delete_ike_sa_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Message sent by our peer, if already generated
	 */
	message_t *message;
	
	/**
	 * Message ID this transaction uses
	 */
	u_int32_t message_id;
	
	/**
	 * Times we did send the request
	 */
	u_int32_t requested;
	
	/**
	 * Assigned logger.
	 */
	logger_t *logger;
};

/**
 * Implementation of transaction_t.get_message_id.
 */
static u_int32_t get_message_id(private_delete_ike_sa_t *this)
{
	return this->message_id;
}

/**
 * Implementation of transaction_t.requested.
 */
static u_int32_t requested(private_delete_ike_sa_t *this)
{
	return this->requested++;
}

/**
 * Implementation of transaction_t.get_request.
 */
static status_t get_request(private_delete_ike_sa_t *this, message_t **result)
{
	message_t *request;
	host_t *me, *other;
	delete_payload_t *delete_payload;
	
	/* check if we already have built a message (retransmission) */
	if (this->message)
	{
		*result = this->message;
		return SUCCESS;
	}
	
	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	
	/* build the request */
	request = message_create();
	request->set_source(request, me->clone(me));
	request->set_destination(request, other->clone(other));
	request->set_exchange_type(request, INFORMATIONAL);
	request->set_request(request, TRUE);
	this->message_id = this->ike_sa->get_next_message_id(this->ike_sa);
	request->set_message_id(request, this->message_id);
	request->set_ike_sa_id(request, this->ike_sa->get_id(this->ike_sa));
	/* apply for caller */
	*result = request;
	/* store for retransmission */
	this->message = request;
	
	delete_payload = delete_payload_create(PROTO_IKE);
	request->add_payload(request, (payload_t*)delete_payload);
	
	/* transit to state SA_DELETING */
	this->ike_sa->set_state(this->ike_sa, IKE_DELETING);
	
	return SUCCESS;
}

/**
 * Implementation of transaction_t.get_response.
 */
static status_t get_response(private_delete_ike_sa_t *this, message_t *request, 
							 message_t **result, transaction_t **next)
{
	host_t *me, *other;
	message_t *response;
	iterator_t *payloads;
	delete_payload_t *delete_request = NULL;
	
	/* check if we already have built a response (retransmission) 
	 * this only happens in special simultanous transaction cases,
	 * as we delete the IKE_SA after the response is sent. */
	if (this->message)
	{
		*result = this->message;
		return SUCCESS;
	}
	
	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	this->message_id = request->get_message_id(request);
	
	/* set up response */
	response = message_create();
	response->set_source(response, me->clone(me));
	response->set_destination(response, other->clone(other));
	response->set_exchange_type(response, INFORMATIONAL);
	response->set_request(response, FALSE);
	response->set_message_id(response, this->message_id);
	response->set_ike_sa_id(response, this->ike_sa->get_id(this->ike_sa));
	this->message = response;
	*result = response;
	
	/* check message type */
	if (request->get_exchange_type(request) != INFORMATIONAL)
	{
		this->logger->log(this->logger, ERROR,
						  "INFORMATIONAL response of invalid type, deleting IKE_SA");
		return DESTROY_ME;
	}
	
	/* iterate over all payloads */
	payloads = request->get_payload_iterator(request);	
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		
		switch (payload->get_type(payload))
		{
			case DELETE:
			{
				delete_request = (delete_payload_t *)payload;
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR|LEVEL1, "ignoring payload %s (%d)",
								  mapping_find(payload_type_m, payload->get_type(payload)),
								  payload->get_type(payload));
				break;
			}
		}
	}
	payloads->destroy(payloads);
	
	if (delete_request && 
		delete_request->get_protocol_id(delete_request) == PROTO_IKE)
	{
		this->logger->log(this->logger, CONTROL, 
						  "DELETE request for IKE_SA received, deleting IKE_SA");
	}
	else
	{
		/* should not happen, as we preparsed this at transaction construction */
		this->logger->log(this->logger, CONTROL, 
						  "received a weird DELETE request for IKE_SA, deleting anyway");
	}
	if (this->ike_sa->get_state(this->ike_sa) == IKE_DELETING)
	{
		/* if we are already deleting an IKE_SA, we do not destroy. We wait
		 * until we get the response for our initiated delete. */
		return SUCCESS;
	}
	this->ike_sa->set_state(this->ike_sa, IKE_DELETING);
	return DESTROY_ME;
}


/**
 * Implementation of transaction_t.conclude
 */
static status_t conclude(private_delete_ike_sa_t *this, message_t *response, 
						 transaction_t **transaction)
{
	/* check message type */
	if (response->get_exchange_type(response) != INFORMATIONAL)
	{
		this->logger->log(this->logger, ERROR,
						  "INFORMATIONAL response of invalid type, deleting IKE_SA");
		return DESTROY_ME;
	}
	/* this is only an acknowledge. We can't do anything here, but delete
	 * the IKE_SA. */
	return DESTROY_ME;
}

/**
 * implements transaction_t.destroy
 */
static void destroy(private_delete_ike_sa_t *this)
{
	DESTROY_IF(this->message);
	free(this);
}

/*
 * Described in header.
 */
delete_ike_sa_t *delete_ike_sa_create(ike_sa_t *ike_sa)
{
	private_delete_ike_sa_t *this = malloc_thing(private_delete_ike_sa_t);
	
	/* transaction interface functions */
	this->public.transaction.get_request = (status_t(*)(transaction_t*,message_t**))get_request;
	this->public.transaction.get_response = (status_t(*)(transaction_t*,message_t*,message_t**,transaction_t**))get_response;
	this->public.transaction.conclude = (status_t(*)(transaction_t*,message_t*,transaction_t**))conclude;
	this->public.transaction.get_message_id = (u_int32_t(*)(transaction_t*))get_message_id;
	this->public.transaction.requested = (u_int32_t(*)(transaction_t*))requested;
	this->public.transaction.destroy = (void(*)(transaction_t*))destroy;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->message_id = 0;
	this->message = NULL;
	this->requested = 0;
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);
	
	return &this->public;
}
