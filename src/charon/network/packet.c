/**
 * @file packet.c
 * 
 * @brief Implementation of packet_t.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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


typedef struct private_packet_t private_packet_t;

/**
 * Private data of an packet_t object.
 */
struct private_packet_t {

	/**
	 * Public part of a packet_t object.
	 */
	packet_t public;
	
	/**
	 * source address
	 */
	host_t *source;
		
	/**
	 * destination address
	 */
	host_t *destination;
	 
	 /**
	  * message data
	  */
	chunk_t data;
};

/**
 * Implements packet_t.get_source
 */
static void set_source(private_packet_t *this, host_t *source)
{
	if (this->source)
	{
		this->source->destroy(this->source);	
	}
	this->source = source;
}

/**
 * Implements packet_t.set_destination
 */
static void set_destination(private_packet_t *this, host_t *destination)
{
	if (this->destination)
	{
		this->destination->destroy(this->destination);	
	}
	this->destination = destination;
}

/**
 * Implements packet_t.get_source
 */
static host_t *get_source(private_packet_t *this)
{
	return this->source;
}

/**
 * Implements packet_t.get_destination
 */
static host_t *get_destination(private_packet_t *this)
{
	return this->destination;
}
	
/**
 * Implements packet_t.get_data
 */
static chunk_t get_data(private_packet_t *this)
{
	return this->data;
}

/**
 * Implements packet_t.set_data
 */
static void set_data(private_packet_t *this, chunk_t data)
{
	free(this->data.ptr);
	this->data = data;
}

/**
 * Implements packet_t.destroy.
 */
static void destroy(private_packet_t *this)
{
	if (this->source != NULL)
	{
		this->source->destroy(this->source);
	}	
	if (this->destination != NULL)
	{
		this->destination->destroy(this->destination);
	}
	free(this->data.ptr);
	free(this);
}

/**
 * Implements packet_t.clone.
 */
static packet_t *clone(private_packet_t *this)
{
	private_packet_t *other = (private_packet_t*)packet_create();
	
	if (this->destination != NULL)
	{
		other->destination = this->destination->clone(this->destination);
	}
	if (this->source != NULL)
	{
		other->source = this->source->clone(this->source);
	}
	if (this->data.ptr != NULL)
	{
		other->data.ptr = clalloc(this->data.ptr,this->data.len);
		other->data.len = this->data.len;
	}
	return &(other->public);
}

/*
 * Documented in header
 */
packet_t *packet_create(void)
{
	private_packet_t *this = malloc_thing(private_packet_t);

	this->public.set_data = (void(*) (packet_t *,chunk_t)) set_data;
	this->public.get_data = (chunk_t(*) (packet_t *)) get_data;
	this->public.set_source = (void(*) (packet_t *,host_t*)) set_source;
	this->public.get_source = (host_t*(*) (packet_t *)) get_source;
	this->public.set_destination = (void(*) (packet_t *,host_t*)) set_destination;
	this->public.get_destination = (host_t*(*) (packet_t *)) get_destination;
	this->public.clone = (packet_t*(*) (packet_t *))clone;
	this->public.destroy = (void(*) (packet_t *)) destroy;
	
	this->destination = NULL;
	this->source = NULL;
	this->data = CHUNK_INITIALIZER;
	
	return &(this->public);
}
