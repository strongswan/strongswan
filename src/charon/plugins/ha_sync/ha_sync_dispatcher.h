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
 * @defgroup ha_sync_dispatcher ha_sync_dispatcher
 * @{ @ingroup ha-sync
 */

#ifndef HA_SYNC_DISPATCHER_H_
#define HA_SYNC_DISPATCHER_H_

#include "ha_sync_socket.h"
#include "ha_sync_segments.h"

typedef struct ha_sync_dispatcher_t ha_sync_dispatcher_t;

/**
 * The dispatcher pulls sync message in a thread an processes them.
 */
struct ha_sync_dispatcher_t {

	/**
	 * Destroy a ha_sync_dispatcher_t.
	 */
	void (*destroy)(ha_sync_dispatcher_t *this);
};

/**
 * Create a ha_sync_dispatcher instance pulling from socket.
 *
 * @param socket		socket to pull messages from
 * @param segments		segments to control based on received messages
 * @return				dispatcher object
 */
ha_sync_dispatcher_t *ha_sync_dispatcher_create(ha_sync_socket_t *socket,
												ha_sync_segments_t *segments);

#endif /* HA_SYNC_DISPATCHER_ @}*/
