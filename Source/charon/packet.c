/**
 * @file packet.h
 *
 * @brief UDP-Packet, contains data, sender and receiver
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


static status_t destroy(packet_t *this)
{
	if (this->data.ptr != NULL)
	{
		allocator_free(this->data.ptr);
	}
	allocator_free(this);
	return SUCCESS;
}

/**
 * @brief helper function to set address used by set_dest & set_source
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

status_t set_destination(packet_t *this, char *address, u_int16_t port)
{
	struct sockaddr *saddr = &(this->destination);
	return set_addr(this->family, saddr, address, port);
}

status_t set_source(packet_t *this, char *address, u_int16_t port)
{
	struct sockaddr *saddr = &(this->source);
	return set_addr(this->family, saddr, address, port);
}


packet_t *packet_create(int family)
{
	packet_t *this = allocator_alloc_thing(packet_t, "packet_t");

	this->destroy = destroy;
	this->set_destination = set_destination;
	this->set_source = set_source;

	this->family = family;
	switch (family)
	{
		case AF_INET:
			this->sockaddr_len = sizeof(struct sockaddr_in);
			break;
		default: /* not supported */
			allocator_free(this);
			return NULL;
	}

	this->data.len = 0;
	this->data.ptr = NULL;
	return this;
}
