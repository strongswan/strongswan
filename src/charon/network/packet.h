/**
 * @file packet.h
 * 
 * @brief Interface of packet_t.
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
 
#ifndef PACKET_H_
#define PACKET_H_


#include <types.h>
#include <utils/host.h>


typedef struct packet_t packet_t;

/**
 * @brief Abstraction of an UDP-Packet, contains data, sender and receiver.
 * 
 * @b Constructors:
 * - packet_create()
 * 
 * @ingroup network
 */
struct packet_t {

	/**
	 * @brief Set the source address.
	 * 
	 * Set host_t is now owned by packet_t, it will destroy
	 * it if necessary.
	 * 
	 * @param this		calling object
	 * @param source	address to set as source
	 */
	void (*set_source) (packet_t *packet, host_t *source);
	
	/**
	 * @brief Set the destination address.
	 * 
	 * Set host_t is now owned by packet_t, it will destroy
	 * it if necessary.
	 * 
	 * @param this		calling object
	 * @param source	address to set as destination
	 */
	void (*set_destination) (packet_t *packet, host_t *destination);
	
	/**
	 * @brief Get the source address.
	 * 
	 * Set host_t is still owned by packet_t, clone it
	 * if needed.
	 * 
	 * @param this		calling object
	 * @return			source address
	 */
	host_t *(*get_source) (packet_t *packet);
	
	/**
	 * @brief Get the destination address.
	 * 
	 * Set host_t is still owned by packet_t, clone it
	 * if needed.
	 * 
	 * @param this		calling object
	 * @return			destination address
	 */
	host_t *(*get_destination) (packet_t *packet);
	
	/**
	 * @brief Get the data from the packet.
	 * 
	 * The data pointed by the chunk is still owned 
	 * by the packet. Clone it if needed.
	 * 
	 * @param this		calling object
	 * @return			chunk containing the data
	 */
	chunk_t (*get_data) (packet_t *packet);
	
	/**
	 * @brief Set the data in the packet.
	 * 
	 * Supplied chunk data is now owned by the 
	 * packet. It will free it.
	 * 
	 * @param this		calling object
	 * @param data		chunk with data to set
	 */
	void (*set_data) (packet_t *packet, chunk_t data);
	
	/**
	 * @brief Clones a packet_t object.
	 *  
	 * @param packet	calling object
	 * @param clone		pointer to a packet_t object pointer where the new object is stored
	 */
	packet_t* (*clone) (packet_t *packet);
	
	/**
	 * @brief Destroy the packet, freeing contained data.
	 *  
	 * @param packet	packet to destroy	
	 */
	void (*destroy) (packet_t *packet);
};

/**
 * @brief create an empty packet
 *  
 * @return packet_t object
 * 
 * @ingroup network
 */
packet_t *packet_create(void);


#endif /*PACKET_H_*/
