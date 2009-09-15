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
 * @defgroup ha_sync_ike ha_sync_ike
 * @{ @ingroup ha_sync
 */

#ifndef HA_SYNC_IKE_H_
#define HA_SYNC_IKE_H_

#include "ha_sync_socket.h"
#include "ha_sync_tunnel.h"
#include "ha_sync_segments.h"

#include <daemon.h>

typedef struct ha_sync_ike_t ha_sync_ike_t;

/**
 * Listener to synchronize IKE_SAs.
 */
struct ha_sync_ike_t {

	/**
	 * Implements bus listener interface.
	 */
	listener_t listener;

	/**
	 * Destroy a ha_sync_ike_t.
	 */
	void (*destroy)(ha_sync_ike_t *this);
};

/**
 * Create a ha_sync_ike instance.
 *
 * @param socket		socket to use for sending synchronization messages
 * @param tunnel		tunnel securing sync messages, if any
 * @return				IKE listener
 */
ha_sync_ike_t *ha_sync_ike_create(ha_sync_socket_t *socket,
								  ha_sync_tunnel_t *tunnel);

#endif /* HA_SYNC_IKE_ @}*/
