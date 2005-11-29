/**
 * @file packet.h
 * 
 * @brief Interface of packet_t.
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
 
#ifndef PACKET_H_
#define PACKET_H_


#include <types.h>
#include <network/host.h>


typedef struct packet_t packet_t;
/**
 * @brief Abstraction of an UDP-Packet, contains data, sender and receiver.
 * 
 * @ingroup network
 */
struct packet_t {

	/**
	 * source address structure
	 */
	host_t *source;
		
	/**
	 * destination address structure
	 */
	host_t *destination;
	 
	 /**
	  * message data
	  */
	chunk_t data;
		
	/**
	 * @brief 			Clones a packet_t object.
	 *  
	 * @param packet	calling object
	 * @param clone		pointer to a packet_t object pointer where the new object is stored
	 */
	packet_t* (*clone) (packet_t *packet);
	
	/**
	 * @brief 			Destroy the packet, freeing contained data.
	 *  
	 * @param packet	packet to destroy	
	 */
	void (*destroy) (packet_t *packet);
};

/**
 * @brief create an empty packet
 *  
 * @return  			created packet_t object
 * 
 * @ingroup network
 */
packet_t *packet_create();

#endif /*PACKET_H_*/
