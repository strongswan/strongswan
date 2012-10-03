/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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
 * @defgroup lookip_listener lookip_listener
 * @{ @ingroup lookip
 */

#ifndef LOOKIP_LISTENER_H_
#define LOOKIP_LISTENER_H_

#include <bus/listeners/listener.h>

typedef struct lookip_listener_t lookip_listener_t;

/**
 * Listener collecting virtual IPs.
 */
struct lookip_listener_t {

	/**
	 * Implements listener_t interface.
	 */
	listener_t listener;

	/**
	 * Destroy a lookip_listener_t.
	 */
	void (*destroy)(lookip_listener_t *this);
};

/**
 * Create a lookip_listener instance.
 */
lookip_listener_t *lookip_listener_create();

#endif /** LOOKIP_LISTENER_H_ @}*/
