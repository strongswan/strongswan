/*
 * Copyright (C) 2009 Martin Willi
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
 * @defgroup ha_sync_kernel ha_sync_kernel
 * @{ @ingroup ha_sync
 */

#ifndef HA_SYNC_KERNEL_H_
#define HA_SYNC_KERNEL_H_

typedef struct ha_sync_kernel_t ha_sync_kernel_t;

#include "ha_sync_segments.h"

/**
 * HA sync segment kernel configuration interface.
 */
struct ha_sync_kernel_t {

	/**
	 * Check if a host is in a segment.
	 *
	 * @param host		host to check
	 * @param segment	segment
	 * @return 			TRUE if host belongs to segment
	 */
	bool (*in_segment)(ha_sync_kernel_t *this, host_t *host, u_int segment);

	/**
	 * Activate a segment at kernel level for all cluster addresses.
	 *
	 * @param segment	segment to activate
	 */
	void (*activate)(ha_sync_kernel_t *this, u_int segment);

	/**
	 * Deactivate a segment at kernel level for all cluster addresses.
	 *
	 * @param segment	segment to deactivate
	 */
	void (*deactivate)(ha_sync_kernel_t *this, u_int segment);

	/**
	 * Destroy a ha_sync_kernel_t.
	 */
	void (*destroy)(ha_sync_kernel_t *this);
};

/**
 * Create a ha_sync_kernel instance.
 *
 * @param count			total number of segments to use
 * @param active		bitmask of initially active segments
 * @param virtuals		comma separated list of virtual cluster addresses
 */
ha_sync_kernel_t *ha_sync_kernel_create(u_int count, segment_mask_t active,
										char *virtuals);

#endif /* HA_SYNC_KERNEL_ @}*/
