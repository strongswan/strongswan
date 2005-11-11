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

#include "utils/allocator.h"


/**
 * Private data of an packet_t object
 */
typedef struct private_packet_s private_packet_t;

struct private_packet_s {

	/**
	 * Public part of a packet_t object
	 */
	packet_t public;
	
	/* private functions */
	
	/**
	 * @brief helper function to set address used by set_dest & set_source.
	 * 
	 * @param this 		calling object_t
	 * @param family 	address family
	 * @param saddr		source address
	 * @param address 	address as string
	 * @return			
	 * 					- SUCCESS if successfuly
	 * 					- NOT_SUPPORTED if family is not supported
	 */
	status_t (*set_addr) (private_packet_t *this, int family, struct sockaddr *saddr, char *address, u_int16_t port);
};

/**
 * Implements packet_t's destroy function.
 * See #packet_s.destroy for description.
 */
static status_t destroy(private_packet_t *this)
{
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
static status_t clone (private_packet_t *packet, packet_t **clone)
{
	*clone = packet_create(packet->public.family);
	if ((*clone) == NULL)
	{

		return OUT_OF_RES;
	}

	
	(*clone)->sockaddr_len = packet->public.sockaddr_len;
	(*clone)->source = packet->public.source;
	(*clone)->destination = packet->public.destination;
	/* only clone existing chunks :-) */
	if (packet->public.data.ptr != NULL)
	{
		(*clone)->data.ptr = allocator_clone_bytes(packet->public.data.ptr,packet->public.data.len);
		if ((*clone)->data.ptr == NULL)
		{
			(*clone)->destroy((*clone));
			return OUT_OF_RES;
		}
		(*clone)->data.len = packet->public.data.len;
	}
	return SUCCESS;
}

/**
 * Implements private_packet_t's set_addr function.
 * See #private_packet_t.set_addr for description.
 */
static status_t set_addr(int family, struct sockaddr *saddr, char *address, u_int16_t port)
{
	switch (family)
	{
		/* IPv4 */
		case AF_INET:
			{
				struct sockaddr_in *sin = (struct sockaddr_in*)saddr;
				sin->sin_family = AF_INET;
				sin->sin_addr.s_addr = inet_addr("127.0.0.1");
				sin->sin_port = htons(port);
				return SUCCESS;;
			}
	}
	return NOT_SUPPORTED;
}

/**
 * Implements packet_t's set_destination function.
 * See #packet_t.set_destination for description.
 */
static status_t set_destination(packet_t *this, char *address, u_int16_t port)
{
	struct sockaddr *saddr = &(this->destination);
	return set_addr(this->family, saddr, address, port);
}

/**
 * Implements packet_t's set_source function.
 * See #packet_t.set_source for description.
 */
static status_t set_source(packet_t *this, char *address, u_int16_t port)
{
	struct sockaddr *saddr = &(this->source);
	return set_addr(this->family, saddr, address, port);
}

/*
 * Documented in header
 */
packet_t *packet_create(int family)
{
	private_packet_t *this = allocator_alloc_thing(private_packet_t);

	this->public.destroy = (status_t(*) (packet_t *)) destroy;
	this->public.set_destination = set_destination;
	this->public.set_source = set_source;
	this->public.clone = (status_t(*) (packet_t *,packet_t**))clone;

	this->public.family = family;
	switch (family)
	{
		case AF_INET:
			this->public.sockaddr_len = sizeof(struct sockaddr_in);
			break;
		default: /* not supported */
			allocator_free(this);
			return NULL;
	}

	this->public.data.len = 0;
	this->public.data.ptr = NULL;
	return &(this->public);
}
