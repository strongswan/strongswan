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
 
#ifndef PACKET_H_
#define PACKET_H_


#include "types.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>


/**
 * @brief UDP-Packet, contains data, sender and receiver
 */
typedef struct packet_s packet_t;
struct packet_s {
	/**
	 * Address family, such as AF_INET
	 */
	int family;
	size_t sockaddr_len;
	
	/**
	 * source address structure
	 */
	struct sockaddr source;
		
	/**
	 * destination address structure
	 */
	struct sockaddr destination;
	 
	 /**
	  * message data
	  */
	chunk_t data;
	
	status_t (*set_destination) (packet_t *packet, char *address, u_int16_t port);
	status_t (*set_source) (packet_t *packet, char *address, u_int16_t port);
	
	/**
	 * @brief 
	 *  
	 * @param 
	 * @return  
	 */
	status_t (*destroy) (packet_t *packet);
};

/**
 * @brief 
 *  
 * @param 
 * @return  
 */
packet_t *packet_create(int family);

#endif /*PACKET_H_*/
