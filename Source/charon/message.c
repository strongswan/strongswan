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

#include "allocator.h"
#include "types.h"
#include "message.h"
#include "linked_list.h"

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
 * Implements message_t's destroy function.
 * See #message_s.destroy.
 */
static status_t destroy (private_message_t *this)
{
	if (this->packet != NULL)
	{
		this->packet->destroy(this->packet);
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
	this->public.destroy = (status_t(*)(message_t*))destroy;

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
