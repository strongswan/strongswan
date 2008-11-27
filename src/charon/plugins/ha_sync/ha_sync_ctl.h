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
 * @defgroup ha_sync_ctl ha_sync_ctl
 * @{ @ingroup ha_sync
 */

#ifndef HA_SYNC_CTL_H_
#define HA_SYNC_CTL_H_

#include "ha_sync_cache.h"

typedef struct ha_sync_ctl_t ha_sync_ctl_t;

/**
 * HA Sync control interface using a FIFO.
 */
struct ha_sync_ctl_t {

	/**
	 * Destroy a ha_sync_ctl_t.
	 */
	void (*destroy)(ha_sync_ctl_t *this);
};

/**
 * Create a ha_sync_ctl instance.
 *
 * @param cache		cache to control in this socket
 * @return			HA sync control interface
 */
ha_sync_ctl_t *ha_sync_ctl_create(ha_sync_cache_t *cache);

#endif /* HA_SYNC_CTL_ @}*/
