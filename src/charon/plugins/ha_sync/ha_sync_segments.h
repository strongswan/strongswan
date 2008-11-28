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
 *
 * $Id$
 */

/**
 * @defgroup ha_sync_segments ha_sync_segments
 * @{ @ingroup ha_sync
 */

#ifndef HA_SYNC_SEGMENTS_H_
#define HA_SYNC_SEGMENTS_H_

#include <daemon.h>

typedef struct ha_sync_segments_t ha_sync_segments_t;

/**
 * Locally segmentsd HA state synced from other nodes.
 */
struct ha_sync_segments_t {

	/**
	 * Activate a set of IKE_SAs identified by a segments.
	 *
	 * Activating means do a takeover of SAs as the responsible node has failed.
	 * This involves moving all SAs to the daemons IKE_SA manager and handle
	 * them actively now.
	 *
	 * @param segments	numerical segments to takeover
	 */
	void (*activate)(ha_sync_segments_t *this, u_int segments);

	/**
	 * Deactivate a set of IKE_SAs identified by a segments.
	 *
	 * @param segments	numerical segments to takeover
	 */
	void (*deactivate)(ha_sync_segments_t *this, u_int segments);

	/**
	 * Destroy a ha_sync_segments_t.
	 */
	void (*destroy)(ha_sync_segments_t *this);
};

/**
 * Create a ha_sync_segments instance.
 */
ha_sync_segments_t *ha_sync_segments_create();

#endif /* HA_SYNC_SEGMENTS_ @}*/
