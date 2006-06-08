/**
 * @file delete_ike_sa_requested.c
 *
 * @brief Implementation of delete_ike_sa_requested_t.
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

#include "delete_ike_sa_requested.h"

#include <daemon.h>


typedef struct private_delete_ike_sa_requested_t private_delete_ike_sa_requested_t;

/**
 * Private data of a delete_ike_sa_requested_t object.
 */
struct private_delete_ike_sa_requested_t {
	
	/**
	 * methods of the state_t interface
	 */
	delete_ike_sa_requested_t public;
	
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
 * Implements state_t.get_state
 */
static status_t process_message(private_delete_ike_sa_requested_t *this, message_t *message)
{
	ike_sa_id_t *ike_sa_id;
	crypter_t *crypter;
	signer_t *signer;
	status_t status;
	
	/* Notation as follows:
	 * Mx{D} means: Message, with message ID "x", containing a Delete payload
	 *
	 * The clarifcation Document says in 5.8, that a IKE_SA delete should not
	 * be acknowledged with the same delete. This only makes sense for CHILD_SAs,
	 * as they are paired. IKE_SAs are not, there is only one for both ends.
	 *
	 * Normal case:
	 * ----------------
	 * Mx{D}  -->
	 *       <--      Mx{}
	 * Delete request is sent, and we wait for the acknowledge.
	 *
	 * Special case 1:
	 * ---------------
	 * Mx{D}  -->
	 *       <--      My{D}
	 * My{}   -->
	 *       <--      Mx{}
	 * Both initate a delete at the same time. We ack the delete, but wait for
	 * our delete to be acknowledged.
	 */
	
	if (message->get_exchange_type(message) != INFORMATIONAL)
	{
		/* anything other than information is ignored. We can an will not handle
		 * messages such as CREATE_CHILD_SA */
		this->logger->log(this->logger, ERROR | LEVEL1, 
						  "%s messages not supported in state delete_ike_sa_requested. Ignored",
						  mapping_find(exchange_type_m, message->get_exchange_type(message)));
		return FAILED;
	}
	
	if (message->get_request(message))
	{
		/* if it is a request, not a reply to our delete request, we 
		 * just acknowledge this. We stay in our state, as the other peer
		 * has to ACK our request.
		 */
		message_t *acknowledge;
		this->ike_sa->build_message(this->ike_sa, INFORMATIONAL, FALSE, &acknowledge);
		return this->ike_sa->send_response(this->ike_sa, acknowledge);
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
	
	/* parse incoming message, check if it's proper signed */
	status = message->parse_body(message, crypter, signer);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "INFORMATIONAL message decryption failed. Ignoring message");
		return status;
	}
	
	/* ok, he knows about the deletion, destroy this IKE SA */
	return DESTROY_ME;
}

/**
 * Implementation of state_t.get_state.
 */
static ike_sa_state_t get_state(private_delete_ike_sa_requested_t *this)
{
	return DELETE_IKE_SA_REQUESTED;
}

/**
 * Implementation of state_t.get_state
 */
static void destroy(private_delete_ike_sa_requested_t *this)
{
	free(this);
}

/* 
 * Described in header.
 */
delete_ike_sa_requested_t *delete_ike_sa_requested_create(protected_ike_sa_t *ike_sa)
{
	private_delete_ike_sa_requested_t *this = malloc_thing(private_delete_ike_sa_requested_t);

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);
	
	return &(this->public);
}
