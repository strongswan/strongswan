/**
 * @file ike_sa.c
 *
 * @brief Class ike_sa_t. An object of this type is managed by an
 * ike_sa_manager_t-object and represents an IKE_SA
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

#include "types.h"
#include "linked_list.h"
#include "ike_sa.h"


/**
 * States in which a IKE_SA can actually be
 */
typedef enum ike_sa_state_e ike_sa_state_t;

enum ike_sa_state_e{

	/**
	 * IKE_SA is is not in a state
	 */
	NO_STATE,

	/**
	 * A IKE_SA_INIT-message was sent: role initiator
	 */
	IKE_SA_INIT_REQUESTED,

	/**
	 * A IKE_SA_INIT-message was replied: role responder
	 */
	IKE_SA_INIT_RESPONDED,

	/**
	 * An IKE_AUTH-message was sent after a successful
	 * IKE_SA_INIT-exchange: role initiator
	 */
	IKE_AUTH_REQUESTED,

	/**
	 * An IKE_AUTH-message was replied: role responder.
	 * In this state, all the informations for an IKE_SA
	 * and one CHILD_SA are known.
	 */
	IKE_SA_INITIALIZED
};


/**
 * Private data of an message_t object
 */
typedef struct private_ike_sa_s private_ike_sa_t;

struct private_ike_sa_s {

	/**
	 * Public part of a ike_sa_t object
	 */
	ike_sa_t public;


	/* Private values */
	/**
	 * Identifier for the current IKE_SA
	 */
	ike_sa_id_t *ike_sa_id;

	/**
	 * Linked List containing the child sa's of the current IKE_SA
	 */
	linked_list_t *child_sas;

	/**
	 * Current state of the IKE_SA
	 */
	ike_sa_state_t current_state;
};

/**
 * @brief implements function process_message of private_ike_sa_t
 */
static status_t process_message (private_ike_sa_t *this, message_t *message)
{
	/* @TODO Add Message Processing here */
	return SUCCESS;
}

/**
 * @brief implements function process_configuration of private_ike_sa_t
 */
static status_t process_configuration (private_ike_sa_t *this,configuration_t *configuration)
{
	/*
	 * @TODO Add configuration processing here
	 */
	return SUCCESS;
}

/**
 * @brief implements function private_ike_sa_t.get_id
 */
static ike_sa_id_t* get_id(private_ike_sa_t *this)
{
	return this->ike_sa_id;
}

/**
 * @brief implements function destroy of private_ike_sa_t
 */
static status_t destroy (private_ike_sa_t *this)
{
	if (this == NULL)
	{
		return FAILED;
	}

	this->ike_sa_id->destroy(this->ike_sa_id);

	this->child_sas->destroy(this->child_sas);

	allocator_free(this);

	return SUCCESS;
}

/*
 * Described in Header
 */
ike_sa_t * ike_sa_create(ike_sa_id_t *ike_sa_id)
{
	private_ike_sa_t *this = allocator_alloc_thing(private_ike_sa_t, "private_ike_sa_t");
	if (this == NULL)
	{
		return NULL;
	}


	/* Public functions */
	this->public.process_message = (status_t(*)(ike_sa_t*, message_t*)) process_message;
	this->public.process_configuration = (status_t(*)(ike_sa_t*, configuration_t*)) process_configuration;
	this->public.get_id = (ike_sa_id_t*(*)(ike_sa_t*)) get_id;
	this->public.destroy = (status_t(*)(ike_sa_t*))destroy;


	/* initialize private fields */
	if (ike_sa_id->clone(ike_sa_id,&(this->ike_sa_id)) != SUCCESS)
	{
		allocator_free(this);
		return NULL;
	}

	this->child_sas = linked_list_create();
	if (this->child_sas == NULL)
	{
		this->ike_sa_id->destroy(this->ike_sa_id);
		allocator_free(this);
		return NULL;
	}

	/* at creation time, IKE_SA isn't in a specific state */
	this->current_state = NO_STATE;

	return (&this->public);
}
