/**
 * @file message.c
 *
 * @brief Class message_t. Object of this type represents an IKEv2-Message.
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

#include <stdlib.h>

#include "message.h"

#include "types.h"
#include "ike_sa_id.h"
#include "utils/linked_list.h"
#include "utils/allocator.h"
#include "encodings/encodings.h"

/**
 * Entry for a payload in the internal used linked list
 * 
 */
typedef struct payload_entry_s payload_entry_t;

struct payload_entry_s{
	/**
	 * Type of payload
	 */
	payload_type_t payload_type;
	/**
	 * Data struct holding the data of given payload
	 */
	void *data_struct;
};


/**
 * Private data of an message_t object
 */
typedef struct private_message_s private_message_t;

struct private_message_s {

	/**
	 * Public part of a message_t object
	 */
	message_t public;


	/* Private values */
	/**
	 * Assigned exchange type
	 */
	 exchange_type_t exchange_type;
	
	/**
	 * TRUE if message is from original initiator, FALSE otherwise.
	 */
	bool original_initiator;

	/**
	 * TRUE if message is request.
	 * FALSE if message is reply.
	 */
	bool is_request;
	
	/**
	 * First Payload type following the header
	 */
	payload_type_t first_payload_type;
	
	/**
	 * Message ID of this message
	 */
	u_int32_t message_id;
	
	/**
	 * ID of assigned IKE_SA
	 */
	ike_sa_id_t *ike_sa_id;
	
	/**
	 * Assigned UDP packet.
	 * 
	 * Stores incoming packet or last generated one.
	 */
	 packet_t *packet;
	 
	 /**
	  * Linked List where payload data are stored in
	  */
	linked_list_t *payloads;
};


/**
 * Implements message_t's set_ike_sa_id function.
 * See #message_s.set_ike_sa_id.
 */
static status_t set_ike_sa_id (private_message_t *this,ike_sa_id_t *ike_sa_id)
{
	status_t status;
	status = ike_sa_id->clone(ike_sa_id,&(this->ike_sa_id));
	return status;
}

/**
 * Implements message_t's get_ike_sa_id function.
 * See #message_s.get_ike_sa_id.
 */
static status_t get_ike_sa_id (private_message_t *this,ike_sa_id_t **ike_sa_id)
{
	status_t status;
	if (this->ike_sa_id == NULL)
	{
		return FAILED;
	}
	status = this->ike_sa_id->clone(this->ike_sa_id,ike_sa_id);
	return status;
}


/**
 * Implements message_t's set_message_id function.
 * See #message_s.set_message_id.
 */
static status_t set_message_id (private_message_t *this,u_int32_t message_id)
{
	this->message_id = message_id;
	return SUCCESS;
}


/**
 * Implements message_t's set_message_id function.
 * See #message_s.set_message_id.
 */
static u_int32_t get_message_id (private_message_t *this)
{
	return this->message_id;
}


/**
 * Implements message_t's set_exchange_type function.
 * See #message_s.set_exchange_type.
 */
static status_t set_exchange_type (private_message_t *this,exchange_type_t exchange_type)
{
	this->exchange_type = exchange_type;
	return SUCCESS;
}


/**
 * Implements message_t's get_exchange_type function.
 * See #message_s.get_exchange_type.
 */
static exchange_type_t get_exchange_type (private_message_t *this)
{
	return this->exchange_type;
}

/**
 * Implements message_t's set_original_initiator function.
 * See #message_s.set_original_initiator.
 */
static status_t set_original_initiator (private_message_t *this,bool original_initiator)
{
	this->original_initiator = original_initiator;
	return SUCCESS;
}

/**
 * Implements message_t's get_original_initiator function.
 * See #message_s.get_original_initiator.
 */
static exchange_type_t get_original_initiator (private_message_t *this)
{
	return this->original_initiator;
}

/**
 * Implements message_t's set_request function.
 * See #message_s.set_request.
 */
static status_t set_request (private_message_t *this,bool request)
{
	this->is_request = request;
	return SUCCESS;
}

/**
 * Implements message_t's get_request function.
 * See #message_s.get_request.
 */
static exchange_type_t get_request (private_message_t *this)
{
	return this->is_request;
}

/**
 * Implements message_t's generate_packet function.
 * See #message_s.generate_packet.
 */
static status_t generate_packet (private_message_t *this, packet_t **packet)
{
	if (this->exchange_type == NOT_SET)
	{
		return EXCHANGE_TYPE_NOT_SET;
	}
	
	
	return SUCCESS;
}

/**
 * Implements message_t's destroy function.
 * See #message_s.destroy.
 */
static status_t destroy (private_message_t *this)
{
	if (this->packet != NULL)
	{
		this->packet->destroy(this->packet);
	}
	if (this->ike_sa_id != NULL)
	{
		this->ike_sa_id->destroy(this->ike_sa_id);
	}
	this->payloads->destroy(this->payloads);
	allocator_free(this);
	return SUCCESS;
}

/*
 * Described in Header-File
 */
message_t *message_create_from_packet(packet_t *packet)
{
	private_message_t *this = allocator_alloc_thing(private_message_t);
	if (this == NULL)
	{
		return NULL;
	}

	/* public functions */
	this->public.set_message_id = (status_t(*)(message_t*, u_int32_t))set_message_id;
	this->public.get_message_id = (u_int32_t(*)(message_t*))get_message_id;
	this->public.set_ike_sa_id = (status_t(*)(message_t*, ike_sa_id_t *))set_ike_sa_id;
	this->public.get_ike_sa_id = (status_t(*)(message_t*, ike_sa_id_t **))get_ike_sa_id;
	this->public.set_exchange_type = (status_t(*)(message_t*, exchange_type_t))set_exchange_type;
	this->public.get_exchange_type = (exchange_type_t(*)(message_t*))get_exchange_type;
	this->public.set_original_initiator = (status_t(*)(message_t*, bool))set_original_initiator;
	this->public.get_original_initiator = (bool(*)(message_t*))get_original_initiator;
	this->public.set_request = (status_t(*)(message_t*, bool))set_request;
	this->public.get_request = (bool(*)(message_t*))get_request;
	this->public.generate_packet = (status_t (*) (message_t *, packet_t **)) generate_packet;
	this->public.destroy = (status_t(*)(message_t*))destroy;
		
	/* public values */
	this->exchange_type = NOT_SET;
 	this->original_initiator = TRUE;
 	this->is_request = TRUE;
 	this->first_payload_type = NO_PAYLOAD;
 	this->ike_sa_id = NULL;
 	this->message_id = 0;

	/* private values */
	this->packet = packet;
	this->payloads = linked_list_create();
	if (this->payloads == NULL)
	{
		allocator_free(this);
		return NULL;
	}

	return (&this->public);
}

/*
 * Described in Header-File
 */
message_t *message_create()
{
	return message_create_from_packet(NULL);
}
