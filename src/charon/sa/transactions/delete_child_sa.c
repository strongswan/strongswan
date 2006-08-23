/**
 * @file delete_child_sa.c
 *
 * @brief Implementation of the delete_child_sa transaction.
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

#include "delete_child_sa.h"

#include <daemon.h>
#include <encoding/payloads/delete_payload.h>
#include <sa/transactions/create_child_sa.h>


typedef struct private_delete_child_sa_t private_delete_child_sa_t;

/**
 * Private members of a delete_child_sa_t object..
 */
struct private_delete_child_sa_t {
	
	/**
	 * Public methods and transaction_t interface.
	 */
	delete_child_sa_t public;
	
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
	 * CHILD SA to delete
	 */
	child_sa_t *child_sa;
	
	/**
	 * Assigned logger.
	 */
	logger_t *logger;
};

/**
 * Implementation of transaction_t.get_message_id.
 */
static u_int32_t get_message_id(private_delete_child_sa_t *this)
{
	return this->message_id;
}

/**
 * Implementation of transaction_t.requested.
 */
static u_int32_t requested(private_delete_child_sa_t *this)
{
	return this->requested++;
}

/**
 * Implementation of delete_child_sa_t.set_child_sa.
 */
static void set_child_sa(private_delete_child_sa_t *this, child_sa_t *child_sa)
{
	this->child_sa = child_sa;
}

/**
 * Implementation of transaction_t.get_request.
 */
static status_t get_request(private_delete_child_sa_t *this, message_t **result)
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
	*result = request;
	this->message = request;
	
	{	/* add delete payload */
		delete_payload_t *delete_payload;
		protocol_id_t protocol;
		u_int32_t spi;
		
		protocol = this->child_sa->get_protocol(this->child_sa);
		spi = this->child_sa->get_spi(this->child_sa, TRUE);
		delete_payload = delete_payload_create(protocol);
		
		this->logger->log(this->logger, CONTROL,
						  "created DELETE payload for %s CHILD_SA with SPI 0x%x",
						  mapping_find(protocol_id_m, protocol), htonl(spi));
		delete_payload->add_spi(delete_payload, spi);
		request->add_payload(request, (payload_t*)delete_payload);
	}
	
	this->child_sa->set_state(this->child_sa, CHILD_DELETING);
	
	return SUCCESS;
}

/**
 * process a delete payload
 */
static status_t process_delete(private_delete_child_sa_t *this, delete_payload_t *delete_request, message_t *response)
{
	protocol_id_t protocol;
	u_int32_t spi;
	iterator_t *iterator;
	delete_payload_t *delete_response = NULL;
	
	/* get requested CHILD */
	protocol = delete_request->get_protocol_id(delete_request);
	if (protocol != PROTO_ESP && protocol != PROTO_AH)
	{
		this->logger->log(this->logger, CONTROL,
						  "CHILD_SA delete response contained unexpected protocol");
		return FAILED;
	}
	
	/* prepare response payload */
	if (response)
	{
		delete_response = delete_payload_create(protocol);
		response->add_payload(response, (payload_t*)delete_response);
	}

	iterator = delete_request->create_spi_iterator(delete_request);
	while (iterator->iterate(iterator, (void**)&spi))
	{
		child_sa_t *child_sa;
		
		child_sa = this->ike_sa->get_child_sa(this->ike_sa, protocol, spi, FALSE);
		
		if (child_sa != NULL)
		{
			create_child_sa_t *rekey;
			
			child_sa->set_state(child_sa, CHILD_DELETING);
			
			this->logger->log(this->logger, CONTROL,
							  "received DELETE for %s CHILD_SA with SPI 0x%x, deleting",
							  mapping_find(protocol_id_m, protocol), ntohl(spi));
			
			rekey = child_sa->get_rekeying_transaction(child_sa);
			if (rekey)
			{
				/* we have received a delete for an SA which we are still rekeying.
				 * this means we have lost the nonce comparison, and the rekeying
				 * will fail. We set a flag in the transaction for this special case.
				 */
				rekey->cancel(rekey);
			}
			/* delete it, with inbound spi */
			spi = child_sa->get_spi(child_sa, TRUE);
			this->ike_sa->destroy_child_sa(this->ike_sa, protocol, spi);
			/* add delete response to message, if we are responding */
			if (response)
			{
				delete_response->add_spi(delete_response, spi);
			}
		}
		else
		{
			this->logger->log(this->logger, ERROR,
							  "received DELETE for %s CHILD_SA with SPI 0x%x, but no such SA", 
							  mapping_find(protocol_id_m, protocol), ntohl(spi));
		}
	}
	iterator->destroy(iterator);
	return SUCCESS;
}

/**
 * Implementation of transaction_t.get_response.
 */
static status_t get_response(private_delete_child_sa_t *this, message_t *request, 
							 message_t **result, transaction_t **next)
{
	host_t *me, *other;
	message_t *response;
	iterator_t *payloads;
	
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
	
	if (request->get_exchange_type(request) != INFORMATIONAL)
	{
		this->logger->log(this->logger, ERROR,
						  "INFORMATIONAL response of invalid type, aborting");
		return FAILED;
	}
	
	/* we can't handle a delete for a CHILD when we are rekeying. There
	 * is no proper solution for this. We send a empty informational response,
	 * as described in ikev2-clarifications draft */
	if (this->ike_sa->get_state(this->ike_sa) == IKE_REKEYING ||
		this->ike_sa->get_state(this->ike_sa) == IKE_DELETING)
	{
		this->logger->log(this->logger, AUDIT, 
						  "unable to delete CHILD_SA, as rekeying in progress");
		return FAILED;
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
				process_delete(this, (delete_payload_t*)payload, response);
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
	return SUCCESS;
}

/**
 * Implementation of transaction_t.conclude
 */
static status_t conclude(private_delete_child_sa_t *this, message_t *response, 
						 transaction_t **transaction)
{
	iterator_t *payloads;
	
	/* check message type */
	if (response->get_exchange_type(response) != INFORMATIONAL)
	{
		this->logger->log(this->logger, ERROR,
						  "INFORMATIONAL response of invalid type, aborting");
		return FAILED;
	}
	
	/* iterate over all payloads */
	payloads = response->get_payload_iterator(response);
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		
		switch (payload->get_type(payload))
		{
			case DELETE:
			{
				process_delete(this, (delete_payload_t*)payload, NULL);
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
	return SUCCESS;
}

/**
 * implements transaction_t.destroy
 */
static void destroy(private_delete_child_sa_t *this)
{
	DESTROY_IF(this->message);
	free(this);
}

/*
 * Described in header.
 */
delete_child_sa_t *delete_child_sa_create(ike_sa_t *ike_sa)
{
	private_delete_child_sa_t *this = malloc_thing(private_delete_child_sa_t);
	
	/* transaction interface functions */
	this->public.transaction.get_request = (status_t(*)(transaction_t*,message_t**))get_request;
	this->public.transaction.get_response = (status_t(*)(transaction_t*,message_t*,message_t**,transaction_t**))get_response;
	this->public.transaction.conclude = (status_t(*)(transaction_t*,message_t*,transaction_t**))conclude;
	this->public.transaction.get_message_id = (u_int32_t(*)(transaction_t*))get_message_id;
	this->public.transaction.requested = (u_int32_t(*)(transaction_t*))requested;
	this->public.transaction.destroy = (void(*)(transaction_t*))destroy;
	
	/* publics */
	this->public.set_child_sa = (void(*)(delete_child_sa_t*,child_sa_t*))set_child_sa;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->message_id = 0;
	this->message = NULL;
	this->requested = 0;
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);
	
	return &this->public;
}
