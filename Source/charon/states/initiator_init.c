/**
 * @file initiator_init.c
 * 
 * @brief Start state of a IKE_SA as initiator
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
 
#include "initiator_init.h"

#include "../utils/allocator.h"

/**
 * Private data of a initiator_init_t object.
 *
 */
typedef struct private_initiator_init_s private_initiator_init_t;
struct private_initiator_init_s {
	/**
	 * methods of the state_t interface
	 */
	initiator_init_t public;
	
};

static status_t initiate_connection (private_initiator_init_t *this, char *name, state_t **new_state)
{
	return SUCCESS;
}

/**
 * Implements state_t.get_state
 */
static status_t process_message(private_initiator_init_t *this, message_t *message, state_t **new_state)
{
	*new_state = (state_t *) this;
	return FAILED;
}

/**
 * Implements state_t.get_state
 */
static ike_sa_state_t get_state(private_initiator_init_t *this)
{
	return INITIATOR_INIT;
}

/**
 * Implements state_t.get_state
 */
static status_t destroy(private_initiator_init_t *this)
{
	allocator_free(this);
	return SUCCESS;
}

/* 
 * Described in header.
 */
initiator_init_t *initiator_init_create()
{
	private_initiator_init_t *this = allocator_alloc_thing(private_initiator_init_t);
	
	if (this == NULL)
	{
		return NULL;
	}

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *,state_t **)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (status_t (*) (state_t *)) destroy;
	
	/* public functions */
	this->public.initiate_connection = (status_t (*)(initiator_init_t *, char *, state_t **)) initiate_connection;
	
	return &(this->public);
}
