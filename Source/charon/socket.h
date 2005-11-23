/**
 * @file socket.h
 * 
 * @brief management of sockets
 * 
 * receiver reads from here, sender writes to here
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

#ifndef SOCKET_H_
#define SOCKET_H_


#include <types.h>
#include <packet.h>


/**
 * maximum size of a packet
 * 3000 Bytes should be sufficient, see IKEv2 draft
 */
#define MAX_PACKET 3000


/**
 * @brief abstraction of one (ipv4), or in future, of multiple sockets
 * 
 */
typedef struct socket_s socket_t;
struct socket_s {
	/**
	 * @brief receive a packet
	 * 
	 * reads a packet from one of the sockets.
	 * source will be set, dest not implemented
	 * 
	 * 
	 * @param sock			socket_t object to work on
	 * @param packet		pinter gets address from allocated packet_t
	 * @return 				FAILED when unable to receive
	 * 						SUCCESS when packet successfully received
	 */
	status_t (*receive) (socket_t *sock, packet_t **packet);
	
	/**
	 * @brief send a packet
	 * 
	 * sends a packet via desired socket.
	 * uses source and dest in packet.
	 * 
	 * @param sock			socket_t object to work on
	 * @param packet[out]	packet_t to send
	 * @return 				FAILED when unable to send
	 * 						SUCCESS when packet successfully sent
	 */
	status_t (*send) (socket_t *sock, packet_t *packet);
	
	/**
	 * @brief destroy sockets
	 * 
	 * close sockets and destroy socket_t object
	 * 
	 * @param sock 			socket_t to destroy
	 * @return 				SUCCESS
	 */
	status_t (*destroy) (socket_t *sock);
};

/**
 * @brief socket_t constructor
 * 
 * currently creates one socket, listening on all addresses
 * on port.
 *  
 * @param port				port to bind socket to
 * @return  				the created socket, or NULL on error
 */
socket_t *socket_create(u_int16_t port);


#endif /*SOCKET_H_*/
