/*
 * Copyright (C) 2008 Martin Willi
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
 * @defgroup ha_sync_socket ha_sync_socket
 * @{ @ingroup ha_sync
 */

#ifndef HA_SYNC_SOCKET_H_
#define HA_SYNC_SOCKET_H_

#include "ha_sync_message.h"

/**
 * UDP port we use for communication
 */
#define HA_SYNC_PORT 4510

typedef struct ha_sync_socket_t ha_sync_socket_t;

/**
 * Socket to send/received SA synchronization data
 */
struct ha_sync_socket_t {

	/**
	 * Push synchronization information to the responsible node.
	 *
	 * @param message	message to send
	 */
	void (*push)(ha_sync_socket_t *this, ha_sync_message_t *message);

	/**
	 * Pull synchronization information from a peer we are responsible.
	 *
	 * @return			received message
	 */
	ha_sync_message_t *(*pull)(ha_sync_socket_t *this);

	/**
	 * Destroy a ha_sync_socket_t.
	 */
	void (*destroy)(ha_sync_socket_t *this);
};

/**
 * Create a ha_sync_socket instance.
 */
ha_sync_socket_t *ha_sync_socket_create();

#endif /* HA_SYNC_SOCKET_ @}*/
