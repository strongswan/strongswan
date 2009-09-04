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

/**
 * @defgroup packet packet
 * @{ @ingroup network
 */

#ifndef PACKET_H_
#define PACKET_H_

typedef struct packet_t packet_t;

#include <library.h>
#include <utils/host.h>

/**
 * Abstraction of an UDP-Packet, contains data, sender and receiver.
 */
struct packet_t {

	/**
	 * Set the source address.
	 *
	 * Set host_t is now owned by packet_t, it will destroy
	 * it if necessary.
	 *
	 * @param source	address to set as source
	 */
	void (*set_source) (packet_t *packet, host_t *source);

	/**
	 * Set the destination address.
	 *
	 * Set host_t is now owned by packet_t, it will destroy
	 * it if necessary.
	 *
	 * @param source	address to set as destination
	 */
	void (*set_destination) (packet_t *packet, host_t *destination);

	/**
	 * Get the source address.
	 *
	 * Set host_t is still owned by packet_t, clone it
	 * if needed.
	 *
	 * @return			source address
	 */
	host_t *(*get_source) (packet_t *packet);

	/**
	 * Get the destination address.
	 *
	 * Set host_t is still owned by packet_t, clone it
	 * if needed.
	 *
	 * @return			destination address
	 */
	host_t *(*get_destination) (packet_t *packet);

	/**
	 * Get the data from the packet.
	 *
	 * The data pointed by the chunk is still owned
	 * by the packet. Clone it if needed.
	 *
	 * @return			chunk containing the data
	 */
	chunk_t (*get_data) (packet_t *packet);

	/**
	 * Set the data in the packet.
	 *
	 * Supplied chunk data is now owned by the
	 * packet. It will free it.
	 *
	 * @param data		chunk with data to set
	 */
	void (*set_data) (packet_t *packet, chunk_t data);

	/**
	 * Clones a packet_t object.
	 *
	 * @param clone		clone of the packet
	 */
	packet_t* (*clone) (packet_t *packet);

	/**
	 * Destroy the packet, freeing contained data.
	 */
	void (*destroy) (packet_t *packet);
};

/**
 * create an empty packet
 *
 * @return packet_t object
 */
packet_t *packet_create(void);

#endif /** PACKET_H_ @}*/
