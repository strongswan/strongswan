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


#include "types.h"
#include "packet.h"


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
	 * @brief  
	 * 
	 * 
	 * 
	 * @param  
	 * @return 
	 */
	status_t (*receive) (socket_t *sock, packet_t **packet);
	
	/**
	 * @brief  
	 * 
	 * 
	 * 
	 * @param  
	 * @return 
	 */
	status_t (*send) (socket_t *sock, packet_t *packet);
	
	/**
	 * @brief  
	 * 
	 * 
	 * 
	 * @param  
	 * @return 
	 */
	status_t (*destroy) (socket_t *sock);
};

/**
 * @brief 
 *  
 * @param 
 * @return  
 */
socket_t *socket_create(u_int16_t port);


#endif /*SOCKET_H_*/
