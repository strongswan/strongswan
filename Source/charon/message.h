/**
 * @file message.h
 *
 * @brief Class message_t. Object of this type represents an IKEv2-Message.
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

#ifndef MESSAGE_H_
#define MESSAGE_H_

#include "types.h"
#include "packet.h"

/**
 * @brief This class is used to represent an IKEv2-Message.
 *
 * An IKEv2-Message is either a request or response.
 */
typedef struct message_s message_t;

struct message_s {

	/**
	 * @brief Destroys a message and all including objects
	 *
	 * @param this 		message_t object
	 * @return 
	 * 					- SUCCESSFUL if succeeded
	 */
	status_t (*destroy) (message_t *this);
};

/**
 * Creates an message_t object from a incoming UDP Packet.
 *
 * @warning the given packet_t object is not copied and gets 
 *			destroyed in message_t's destroy call.
 * 
 * @param packet		packet_t object which is assigned to message					  
 * 
 * @return 
 * 					- created message_t object
 * 					- NULL if out of ressources
 */
message_t * message_create_from_packet(packet_t *packet);


/**
 * Creates an empty message_t object.
 *
 * @return 
 * 					- created message_t object
 * 					- NULL if out of ressources
 */
message_t * message_create();

#endif /*MESSAGE_H_*/
