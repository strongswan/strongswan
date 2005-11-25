/**
 * @file ike_sa_init_responded.c
 * 
 * @brief State of a IKE_SA after responding to an IKE_SA_INIT request
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
 
#include "ike_sa_init_responded.h"

#include <utils/allocator.h>


typedef struct private_ike_sa_init_responded_t private_ike_sa_init_responded_t;

/**
 * Private data of a ike_sa_init_responded_t object.
 *
 */
struct private_ike_sa_init_responded_t {
	/**
	 * methods of the state_t interface
	 */
	ike_sa_init_responded_t public;
	
	/**
	 * Shared secret from DH-Exchange
	 * 
	 * All needed secrets are derived from this shared secret and then passed to the next
	 * state of type ike_sa_established_t
	 */
	chunk_t shared_secret;
	
	/**
	 * Sent nonce used to calculate secrets
	 */
	chunk_t received_nonce;
	
	/**
	 * Sent nonce used to calculate secrets
	 */
	chunk_t sent_nonce;
	
	/**
	 * Assigned IKE_SA
	 */
	protected_ike_sa_t *ike_sa;
	
	/**
	 * Logger used to log data 
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
};

/**
 * Implements state_t.get_state
 */
static status_t process_message(private_ike_sa_init_responded_t *this, message_t *message)
{
	return SUCCESS;
}

/**
 * Implements state_t.get_state
 */
static ike_sa_state_t get_state(private_ike_sa_init_responded_t *this)
{
	return IKE_SA_INIT_RESPONDED;
}

/**
 * Implements state_t.get_state
 */
static status_t destroy(private_ike_sa_init_responded_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy ike_sa_init_responded_t state object");
	
	this->logger->log(this->logger, CONTROL | MOST, "Destroy shared_secret");
	allocator_free(this->shared_secret.ptr);

	this->logger->log(this->logger, CONTROL | MOST, "Destroy sent nonce");
	allocator_free(this->sent_nonce.ptr);

	this->logger->log(this->logger, CONTROL | MOST, "Destroy received nonce");
	allocator_free(this->received_nonce.ptr);
	
	allocator_free(this);
	return SUCCESS;
}

/* 
 * Described in header.
 */
 
ike_sa_init_responded_t *ike_sa_init_responded_create(protected_ike_sa_t *ike_sa, chunk_t shared_secret, chunk_t received_nonce, chunk_t sent_nonce)
{
	private_ike_sa_init_responded_t *this = allocator_alloc_thing(private_ike_sa_init_responded_t);
	
	if (this == NULL)
	{
		return NULL;
	}

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (status_t (*) (state_t *)) destroy;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	this->shared_secret = shared_secret;
	this->received_nonce = received_nonce;
	this->sent_nonce = sent_nonce;
	
	return &(this->public);
}
