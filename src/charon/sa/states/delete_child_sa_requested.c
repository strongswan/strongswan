/**
 * @file delete_child_sa_requested.c
 * 
 * @brief State after a CREATE_CHILD_SA request was sent.
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

#include <string.h>

#include "delete_child_sa_requested.h"

#include <sa/child_sa.h>
#include <sa/states/delete_ike_sa_requested.h>
#include <sa/states/ike_sa_established.h>
#include <encoding/payloads/notify_payload.h>
#include <encoding/payloads/delete_payload.h>
#include <utils/logger_manager.h>


typedef struct private_delete_child_sa_requested_t private_delete_child_sa_requested_t;

/**
 * Private data of a delete_child_sa_requested_t object.
 */
struct private_delete_child_sa_requested_t {
	/**
	 * Public interface of delete_child_sa_requested_t.
	 */
	delete_child_sa_requested_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	protected_ike_sa_t *ike_sa;
	
	/**
	 * Assigned logger.
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
};


/**
 * Process the response
 */
static status_t process_message(private_delete_child_sa_requested_t *this, message_t *response)
{
	ike_sa_id_t *ike_sa_id;
	crypter_t *crypter;
	signer_t *signer;
	status_t status;
	iterator_t *iterator;
	payload_t *payload;
	delete_payload_t *delete_response;
	
	if (response->get_exchange_type(response) != INFORMATIONAL)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "Message of type %s not supported in state delete_child_sa_requested",
						  mapping_find(exchange_type_m, response->get_exchange_type(response)));
		return FAILED;
	}
	
	if (response->get_request(response))
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "INFORMATIONAL requests not allowed state delete_child_sa_requested");
		/* TODO: our state implementation currently can not handle incoming requests cleanly here.
		 * If a request comes in before an outstanding reply, we can not handle it cleanly.
		 * Currently, we create a ESTABLISHED state and let it process the message... But we
		 * need changes in the whole state mechanism.
		 */
		state_t *state = (state_t*)ike_sa_established_create(this->ike_sa);
		state->process_message(state, response);
		state->destroy(state);
		return SUCCESS;
	}
	
	/* get signer for verification and crypter for decryption */
	ike_sa_id = this->ike_sa->public.get_id(&this->ike_sa->public);
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
	status = response->parse_body(response, crypter, signer);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "INFORMATIONAL response decryption failed. Ignoring message");
		return status;
	}
	
	iterator = response->get_payload_iterator(response);
	while (iterator->has_next(iterator)) {
		iterator->current(iterator, (void**)&payload);
		switch (payload->get_type(payload))
		{
			case DELETE:
				delete_response = (delete_payload_t*)payload;
				break;
			default:
				break;
		}
		
	}
	iterator->destroy(iterator);
	
	if (delete_response)
	{
		iterator = delete_response->create_spi_iterator(delete_response);
		while (iterator->has_next(iterator))
		{	
			u_int32_t spi;
			iterator->current(iterator, (void**)&spi);
			this->logger->log(this->logger, CONTROL, "DELETE request for CHILD_SA with SPI 0x%x received", spi);
			this->ike_sa->destroy_child_sa(this->ike_sa, spi);
		}
		iterator->destroy(iterator);
	}
	
	this->ike_sa->set_last_replied_message_id(this->ike_sa, response->get_message_id(response));
	
	/* create new state */
	this->ike_sa->set_new_state(this->ike_sa, (state_t*)ike_sa_established_create(this->ike_sa));
	this->public.state_interface.destroy(&this->public.state_interface);
	
	return SUCCESS;
}

/**
 * Implements state_t.get_state
 */
static ike_sa_state_t get_state(private_delete_child_sa_requested_t *this)
{
	return DELETE_CHILD_SA_REQUESTED;
}

/**
 * Implementation of state_t.destroy.
 */
static void destroy(private_delete_child_sa_requested_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
delete_child_sa_requested_t *delete_child_sa_requested_create(protected_ike_sa_t *ike_sa)
{
	private_delete_child_sa_requested_t *this = malloc_thing(private_delete_child_sa_requested_t);
	
	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);
	
	return &(this->public);
}
