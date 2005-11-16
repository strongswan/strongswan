/**
 * @file packet.h
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
 
#ifndef PACKET_H_
#define PACKET_H_


#include "types.h"
#include "utils/host.h"



/**
 * @brief UDP-Packet, contains data, sender and receiver
 */
typedef struct packet_s packet_t;
struct packet_s {

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
	 * @brief 			Clones a packet_t object
	 *  
	 * @param packet		calling object
	 * @param clone		pointer to a packet_t object pointer where the new object is stored
	 * @return 			- SUCCESS if successful
	 * 					- OUT_OF_RES
	 */
	status_t (*clone) (packet_t *packet, packet_t **clone);
	
	/**
	 * @brief 			destroy the packet, freeing contained data
	 *  
	 * @param packet	packet to destroy	
	 * @return 			- SUCCESS
	 */
	status_t (*destroy) (packet_t *packet);
};

/**
 * @brief create an empty packet
 *  
 * @param family		address-family, such as AF_INET
 * @return  			- NULL when family not supported
 */
packet_t *packet_create();

#endif /*PACKET_H_*/
