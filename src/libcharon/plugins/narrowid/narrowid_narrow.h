/*
 * Copyright (C) 2015 Martin Willi
 * Copyright (C) 2015 revosec AG
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
 * @defgroup narrowid_narrow narrowid_narrow
 * @{ @ingroup narrowid
 */

#ifndef NARROWID_NARROW_H_
#define NARROWID_NARROW_H_

#include <bus/listeners/listener.h>

typedef struct narrowid_narrow_t narrowid_narrow_t;

/**
 * Listener narrowing remote traffic selectors to authenticated IKE IDs.
 */
struct narrowid_narrow_t {

	/**
	 * Implements listener_t.
	 */
	listener_t listener;

	/**
	 * Destroy a narrowid_narrow_t.
	 */
	void (*destroy)(narrowid_narrow_t *this);
};

/**
 * Create a narrowid_narrow instance.
 */
narrowid_narrow_t *narrowid_narrow_create();

#endif /** NARROWID_NARROW_H_ @}*/
