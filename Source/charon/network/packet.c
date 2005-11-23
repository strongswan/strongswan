/**
 * @file packet.c
 * 
 * @brief UDP-Packet, contains data, sender and receiver.
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


#include "packet.h"

#include <utils/allocator.h>


/**
 * Private data of an packet_t object
 */
typedef struct private_packet_s private_packet_t;

struct private_packet_s {

	/**
	 * Public part of a packet_t object
	 */
	packet_t public;
};

/**
 * Implements packet_t's destroy function.
 * See #packet_s.destroy for description.
 */
static status_t destroy(private_packet_t *this)
{
	if (this->public.source != NULL)
	{
		this->public.source->destroy(this->public.source);
	}	
	if (this->public.destination != NULL)
	{
		this->public.destination->destroy(this->public.destination);
	}
	if (this->public.data.ptr != NULL)
	{
		allocator_free(this->public.data.ptr);
	}
	allocator_free(this);
	return SUCCESS;
}

/**
 * Implements packet_t's clone function.
 * See #packet_s.clone for description.
 */
static status_t clone (private_packet_t *this, packet_t **clone)
{
	packet_t *other;
	other = packet_create();
	if (other == NULL)
	{
		return OUT_OF_RES;
	}
	
	if (this->public.destination != NULL)
	{
		this->public.destination->clone(this->public.destination, &(other->destination));
	}
	else {
		other->destination = NULL;
	}
	
	if (this->public.source != NULL)
	{
		this->public.source->clone(this->public.source, &(other->source));
	}
	else {
		other->source = NULL;
	}
	
	/* only clone existing chunks :-) */
	if (this->public.data.ptr != NULL)
	{
		other->data.ptr = allocator_clone_bytes(this->public.data.ptr,this->public.data.len);
		if (other->data.ptr == NULL)
		{
			other->destroy(other);
			return OUT_OF_RES;
		}
		other->data.len = this->public.data.len;
	}
	else
	{
		other->data.ptr = NULL;
		other->data.len = 0;
	}
	*clone = other;
	return SUCCESS;
}


/*
 * Documented in header
 */
packet_t *packet_create()
{
	private_packet_t *this = allocator_alloc_thing(private_packet_t);

	this->public.destroy = (status_t(*) (packet_t *)) destroy;
	this->public.clone = (status_t(*) (packet_t *,packet_t**))clone;
	
	this->public.destination = NULL;
	this->public.source = NULL;

	this->public.data.len = 0;
	this->public.data.ptr = NULL;
	return &(this->public);
}
