/**
 * @file create_child_sa_requested.c
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

#include "create_child_sa_requested.h"

#include <sa/child_sa.h>
#include <encoding/payloads/ts_payload.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <utils/logger_manager.h>


typedef struct private_create_child_sa_requested_t private_create_child_sa_requested_t;

/**
 * Private data of a create_child_sa_requested_t object.
 */
struct private_create_child_sa_requested_t {
	/**
	 * Public interface of create_child_sa_requested_t.
	 */
	create_child_sa_requested_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	protected_ike_sa_t *ike_sa;
	
	/**
	 * nonce chosen by initiator
	 */
	chunk_t nonce_i;
	
	/**
	 * nonce chosen by the responder
	 */
	chunk_t nonce_r;
	
	/**
	 * Assigned logger.
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
};

/**
 * Implements state_t.get_state
 */
static status_t process_message(private_create_child_sa_requested_t *this, message_t *request)
{
	this->logger->log(this->logger, ERROR, "NOT IMPLEMENTED");
}

/**
 * Implements state_t.get_state
 */
static ike_sa_state_t get_state(private_create_child_sa_requested_t *this)
{
	return CREATE_CHILD_SA_REQUESTED;
}

/**
 * Implementation of state_t.destroy.
 */
static void destroy(private_create_child_sa_requested_t *this)
{
	chunk_free(&this->nonce_i);
	chunk_free(&this->nonce_r);
	free(this);
}

/*
 * Described in header.
 */
create_child_sa_requested_t *create_child_sa_requested_create(protected_ike_sa_t *ike_sa, chunk_t nonce_i)
{
	private_create_child_sa_requested_t *this = malloc_thing(private_create_child_sa_requested_t);
	
	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->nonce_i = nonce_i;
	this->nonce_r = CHUNK_INITIALIZER;
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);
	
	return &(this->public);
}
