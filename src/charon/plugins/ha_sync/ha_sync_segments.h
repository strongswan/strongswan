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
 * @defgroup ha_sync_segments ha_sync_segments
 * @{ @ingroup ha_sync
 */

#ifndef HA_SYNC_SEGMENTS_H_
#define HA_SYNC_SEGMENTS_H_

#include "ha_sync_socket.h"

#include <daemon.h>

typedef struct ha_sync_segments_t ha_sync_segments_t;

/**
 * Segmentation of peers into active and passive.
 */
struct ha_sync_segments_t {

	/**
	 * Activate a set of IKE_SAs identified by a segment.
	 *
	 * @param segment	numerical segment to takeover, 0 for all
	 * @param notify	wheter to notify other nodes about activation
	 */
	void (*activate)(ha_sync_segments_t *this, u_int segment, bool notify);

	/**
	 * Deactivate a set of IKE_SAs identified by a segment.
	 *
	 * @param segment	numerical segment to takeover, 0 for all
	 * @param notify	wheter to notify other nodes about deactivation
	 */
	void (*deactivate)(ha_sync_segments_t *this, u_int segment, bool notify);

	/**
	 * Resync an active segment.
	 *
	 * To reintegrade a node into the cluster, resynchronization is reqired.
	 * IKE_SAs and CHILD_SAs are synced automatically during rekeying. A call
	 * to this method enforces a rekeying immediately sync all state of a
	 * segment.
	 *
	 * @param segment	segment to resync
	 */
	void (*resync)(ha_sync_segments_t *this, u_int segment);

	/**
	 * Destroy a ha_sync_segments_t.
	 */
	void (*destroy)(ha_sync_segments_t *this);
};

/**
 * Create a ha_sync_segments instance.
 *
 * @param socket		socket to communicate segment (de-)activation
 * @return				segment object
 */
ha_sync_segments_t *ha_sync_segments_create(ha_sync_socket_t *socket);

#endif /* HA_SYNC_SEGMENTS_ @}*/
