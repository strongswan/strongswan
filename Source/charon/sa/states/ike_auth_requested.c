/**
 * @file ike_auth_requested.c
 * 
 * @brief Implementation of ike_auth_requested_t.
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
 
#include "ike_auth_requested.h"

#include <utils/allocator.h>


typedef struct private_ike_auth_requested_t private_ike_auth_requested_t;

/**
 * Private data of a ike_auth_requested_t object.
 *
 */
struct private_ike_auth_requested_t {
	/**
	 * methods of the state_t interface
	 */
	ike_auth_requested_t public;
	
	/**
	 * Sent nonce value
	 */
	chunk_t sent_nonce;
	
	/**
	 * Received nonce
	 */
	chunk_t received_nonce;
	
	/**
	 * Assigned IKE_SA
	 */
	 protected_ike_sa_t *ike_sa;
};

/**
 * Implements state_t.get_state
 */
static status_t process_message(private_ike_auth_requested_t *this, message_t *message)
{
	return SUCCESS;
}

/**
 * Implements state_t.get_state
 */
static ike_sa_state_t get_state(private_ike_auth_requested_t *this)
{
	return IKE_AUTH_REQUESTED;
}

/**
 * Implements state_t.get_state
 */
static void destroy(private_ike_auth_requested_t *this)
{
	allocator_free(this->sent_nonce.ptr);
	allocator_free(this->received_nonce.ptr);
	allocator_free(this);
}

/* 
 * Described in header.
 */
ike_auth_requested_t *ike_auth_requested_create(protected_ike_sa_t *ike_sa, chunk_t sent_nonce, chunk_t received_nonce)
{
	private_ike_auth_requested_t *this = allocator_alloc_thing(private_ike_auth_requested_t);

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->sent_nonce = sent_nonce;
	this->received_nonce = received_nonce;
	
	
	return &(this->public);
}
