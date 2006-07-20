/**
 * @file dead_peer_detection.c
 *
 * @brief Implementation of the dead_peer_detection transaction.
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

#include "dead_peer_detection.h"

#include <daemon.h>


typedef struct private_dead_peer_detection_t private_dead_peer_detection_t;

/**
 * Private members of a dead_peer_detection_t object..
 */
struct private_dead_peer_detection_t {
	
	/**
	 * Public methods and transaction_t interface.
	 */
	dead_peer_detection_t public;
	
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
static u_int32_t get_message_id(private_dead_peer_detection_t *this)
{
	return this->message_id;
}

/**
 * Implementation of transaction_t.requested.
 */
static u_int32_t requested(private_dead_peer_detection_t *this)
{
	return this->requested++;
}

/**
 * Implementation of transaction_t.get_request.
 */
static status_t get_request(private_dead_peer_detection_t *this, message_t **result)
{
	message_t *request;
	host_t *me, *other;
	
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
	
	return SUCCESS;
}

/**
 * Implementation of transaction_t.get_response.
 */
static status_t get_response(private_dead_peer_detection_t *this, message_t *request, 
							 message_t **result, transaction_t **next)
{
	host_t *me, *other;
	message_t *response;
	
	/* check if we already have built a response (retransmission) */
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
	
	return SUCCESS;
}


/**
 * Implementation of transaction_t.conclude
 */
static status_t conclude(private_dead_peer_detection_t *this, message_t *response, 
						 transaction_t **transaction)
{
	return SUCCESS;
}

/**
 * implements transaction_t.destroy
 */
static void destroy(private_dead_peer_detection_t *this)
{
	DESTROY_IF(this->message);
	free(this);
}

/*
 * Described in header.
 */
dead_peer_detection_t *dead_peer_detection_create(ike_sa_t *ike_sa)
{
	private_dead_peer_detection_t *this = malloc_thing(private_dead_peer_detection_t);
	
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
