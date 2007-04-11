/**
 * @file sender.h
 *
 * @brief Interface of sender_t.
 *
 */

/*
 * Copyright (C) 2005-2007 Martin Willi
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

#ifndef SENDER_H_
#define SENDER_H_

typedef struct sender_t sender_t;

#include <library.h>
#include <network/packet.h>

/**
 * @brief Thread responsible for sending packets over the socket.
 * 
 * @b Constructors:
 *  - sender_create()
 * 
 * @ingroup network
 */
struct sender_t {
	
	/**
	 * @brief Send a packet over the network.
	 *
	 * This function is non blocking and adds the packet to a queue.
	 * Whenever the sender thread things it's good to send the packet,
	 * it'll do so.
	 *
	 * @param this		calling object
 	 * @param packet	packet to send
	 */
	void (*send) (sender_t *this, packet_t *packet);
	
	/**
	 * @brief Destroys a sender object.
	 *
	 * @param this	 	calling object
	 */
	void (*destroy) (sender_t *this);
};

/**
 * @brief Create the sender thread.
 * 
 * The thread will start to work, getting packets
 * from its queue and sends them out.
 * 
 * @return		created sender object
 * 
 * @ingroup network
 */
sender_t * sender_create(void);

#endif /*SENDER_H_*/
