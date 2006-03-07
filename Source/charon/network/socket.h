/**
 * @file socket.h
 * 
 * @brief Interface for socket_t.
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
#include <network/packet.h>


/**
 * @brief Maximum size of a packet.
 * 
 * 3000 Bytes should be sufficient, see IKEv2 RFC.
 * 
 * @ingroup network
 */
#define MAX_PACKET 3000


typedef struct socket_t socket_t;

/**
 * @brief Abstraction all sockets (currently IPv4 only).
 *
 * All available IPv4 sockets are bound and the receive function
 * reads from them. To allow binding of other daemons (pluto) to
 * UDP/500, this implementation uses RAW sockets. An installed
 * "Linux socket filter" filters out all non-IKEv2 traffic and handles
 * just IKEv2 messages. An other daemon (pluto) must handle all traffic
 * seperatly, e.g. ignore IKEv2 traffic, since charon handles that. 
 * 
 * @b Constructors:
 * - socket_create()
 * 
 * @todo add IPv6 support
 * 
 * @todo We currently use multiple sockets for historic reasons. With the
 * new RAW socket mechanism, we could use just one socket and filter
 * addresses in userspace (or via linux socket filter). This would allow 
 * realtime interface/address management in a easy way...
 * 
 * @ingroup network
 */
struct socket_t {
	/**
	 * @brief Receive a packet.
	 * 
	 * Reads a packet from the socket and sets source/dest
	 * appropriately.
	 * 
	 * @param sock			socket_t object to work on
	 * @param packet		pinter gets address from allocated packet_t
	 * @return 				
	 * 						- SUCCESS when packet successfully received
	 * 						- FAILED when unable to receive
	 */
	status_t (*receive) (socket_t *sock, packet_t **packet);
	
	/**
	 * @brief Send a packet.
	 * 
	 * Sends a packet to the net using destination from the packet.
	 * Packet is sent using default routing mechanisms, thus the 
	 * source address in packet is ignored.
	 * 
	 * @param sock			socket_t object to work on
	 * @param packet[out]	packet_t to send
	 * @return 				
	 * 						- SUCCESS when packet successfully sent
	 * 						- FAILED when unable to send
	 */
	status_t (*send) (socket_t *sock, packet_t *packet);
	
	/**
	 * @brief Destroy sockets.
	 * 
	 * close sockets and destroy socket_t object
	 * 
	 * @param sock 			socket_t to destroy
	 */
	void (*destroy) (socket_t *sock);
};

/**
 * @brief Create a socket_t, wich binds multiple sockets.
 * 
 * currently creates one socket, listening on all addresses
 * on "port".
 *  
 * @param port				port to bind socket to
 * @return  				socket_t object
 * 
 * @ingroup network
 */
socket_t *socket_create(u_int16_t port);


#endif /*SOCKET_H_*/
