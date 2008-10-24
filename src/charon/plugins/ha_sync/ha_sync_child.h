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
 * @defgroup ha_sync_child ha_sync_child
 * @{ @ingroup ha_sync
 */

#ifndef HA_SYNC_CHILD_H_
#define HA_SYNC_CHILD_H_

#include <daemon.h>

typedef struct ha_sync_child_t ha_sync_child_t;

/**
 * Synchronize CHILD_SAs.
 */
struct ha_sync_child_t {

	/**
	 * Implements bus listener interface.
	 */
	listener_t listener;

	/**
	 * Destroy a ha_sync_child_t.
	 */
	void (*destroy)(ha_sync_child_t *this);
};

/**
 * Create a ha_sync_child instance.
 */
ha_sync_child_t *ha_sync_child_create();

#endif /* HA_SYNC_CHILD_ @}*/
