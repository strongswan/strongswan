/**
 * @file ike_sa_established.c
 * 
 * @brief Implementation of ike_sa_established_t.
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
 
#include "ike_sa_established.h"

#include <utils/allocator.h>


typedef struct private_ike_sa_established_t private_ike_sa_established_t;

/**
 * Private data of a ike_sa_established_t object.
 */
struct private_ike_sa_established_t {
	/**
	 * methods of the state_t interface
	 */
	ike_sa_established_t public;
	
	/** 
	 * Assigned IKE_SA
	 */
	protected_ike_sa_t *ike_sa;
	
};

/**
 * Implements state_t.get_state
 */
static status_t process_message(private_ike_sa_established_t *this, message_t *message)
{
	return SUCCESS;
}

/**
 * Implements state_t.get_state
 */
static ike_sa_state_t get_state(private_ike_sa_established_t *this)
{
	return IKE_SA_ESTABLISHED;
}

/**
 * Implements state_t.get_state
 */
static void destroy(private_ike_sa_established_t *this)
{
	allocator_free(this);
}

/* 
 * Described in header.
 */
ike_sa_established_t *ike_sa_established_create(protected_ike_sa_t *ike_sa)
{
	private_ike_sa_established_t *this = allocator_alloc_thing(private_ike_sa_established_t);

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private data */
	this->ike_sa = ike_sa;
	
	return &(this->public);
}
