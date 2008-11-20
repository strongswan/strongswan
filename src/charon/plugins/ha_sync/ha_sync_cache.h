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
 * @defgroup ha_sync_cache ha_sync_cache
 * @{ @ingroup ha_sync
 */

#ifndef HA_SYNC_CACHE_H_
#define HA_SYNC_CACHE_H_

#include <daemon.h>

typedef struct ha_sync_cache_t ha_sync_cache_t;

/**
 * Locally cached HA state synced from other nodes.
 */
struct ha_sync_cache_t {

	/**
	 * Get a synced and cached IKE_SA entry.
	 *
	 * If no cached IKE_SA with such an id exists, it gets created.
	 *
	 * @param id		IKE_SA identifier of cached SA.
	 * @return			cached IKE_SA
	 */
	ike_sa_t* (*get_ike_sa)(ha_sync_cache_t *this, ike_sa_id_t *id);

	/**
	 * Check if an IKE_SA is in the cache.
	 *
	 * @param id		IKE_SA identifier of cached SA.
	 * @return			TRUE if IKE_SA found
	 */
	bool (*has_ike_sa)(ha_sync_cache_t *this, ike_sa_id_t *id);

	/**
	 * Delete a synced and cached IKE_SA entry.
	 *
	 * @param id		IKE_SA identifier of cached SA to delete.
	 */
	void (*delete_ike_sa)(ha_sync_cache_t *this, ike_sa_id_t *id);

	/**
	 * Activate a set of IKE_SAs identified by a segment.
	 *
	 * Activating means do a takeover of SAs as the responsible node has failed.
	 * This involves moving all SAs to the daemons IKE_SA manager and handle
	 * them actively now.
	 *
	 * @param segment	numerical segment to takeover
	 */
	void (*activate_segment)(ha_sync_cache_t *this, u_int segment);

	/**
	 * Destroy a ha_sync_cache_t.
	 */
	void (*destroy)(ha_sync_cache_t *this);
};

/**
 * Create a ha_sync_cache instance.
 */
ha_sync_cache_t *ha_sync_cache_create();

#endif /* HA_SYNC_CACHE_ @}*/
