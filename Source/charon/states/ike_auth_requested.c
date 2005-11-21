/**
 * @file ike_auth_requested.c
 * 
 * @brief State of an IKE_SA, which has requested an IKE_AUTH.
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

#include "../utils/allocator.h"

/**
 * Private data of a ike_auth_requested_t object.
 *
 */
typedef struct private_ike_auth_requested_s private_ike_auth_requested_t;
struct private_ike_auth_requested_s {
	/**
	 * methods of the state_t interface
	 */
	ike_auth_requested_t public;
	
};

/**
 * Implements state_t.get_state
 */
static status_t process_message(private_ike_auth_requested_t *this, message_t *message, state_t **new_state)
{
	*new_state = (state_t *) this;
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
static status_t destroy(private_ike_auth_requested_t *this)
{
	allocator_free(this);
	return SUCCESS;
}

/* 
 * Described in header.
 */
ike_auth_requested_t *ike_auth_requested_create()
{
	private_ike_auth_requested_t *this = allocator_alloc_thing(private_ike_auth_requested_t);
	
	if (this == NULL)
	{
		return NULL;
	}

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *,state_t **)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (status_t (*) (state_t *)) destroy;
	
	return &(this->public);
}
