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
 * @defgroup stroke_counter stroke_counter
 * @{ @ingroup stroke
 */

#ifndef STROKE_COUNTER_H_
#define STROKE_COUNTER_H_

#include <bus/listeners/listener.h>

typedef struct stroke_counter_t stroke_counter_t;

/**
 * Collection of counter values for different IKE events.
 */
struct stroke_counter_t {

	/**
	 * Implements listener_t.
	 */
	listener_t listener;

	/**
	 * Destroy a stroke_counter_t.
	 */
	void (*destroy)(stroke_counter_t *this);
};

/**
 * Create a stroke_counter instance.
 */
stroke_counter_t *stroke_counter_create();

#endif /** STROKE_COUNTER_H_ @}*/
