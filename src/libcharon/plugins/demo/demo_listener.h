/*
 * Copyright (C) 2015-2016 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup demo_listener demo_listener
 * @{ @ingroup demo
 */

#ifndef DEMO_LISTENER_H_
#define DEMO_LISTENER_H_


#include <bus/listeners/listener.h>

typedef struct demo_listener_t demo_listener_t;

/**
 * Insert and process DEMO notify payload
 */
struct demo_listener_t {

	/**
	 * Implements a listener.
	 */
	listener_t listener;

	/**
	 * Destroy a demo_listener_t.
	 */
	void (*destroy)(demo_listener_t *this);
};

/**
 * Create a demo_listener instance.
 */
demo_listener_t *demo_listener_create();

#endif /** DEMO_LISTENER_H_ @}*/
