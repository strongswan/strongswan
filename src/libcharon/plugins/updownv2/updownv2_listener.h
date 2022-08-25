/*
 * Copyright (C) 2008 Martin Willi
 * Copyright (C) 2022 Noel Kuntze
 *
 * Copyright (C) secunet Security Networks AG
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
 * @defgroup updownv2_listener updownv2_listener
 * @{ @ingroup updown
 */

#ifndef updownv2_LISTENER_H_
#define updownv2_LISTENER_H_

#include <bus/bus.h>

#include "updownv2_handler.h"

typedef struct updownv2_listener_t updownv2_listener_t;

typedef enum updown_bus_events_t updown_bus_events_t;

enum updown_bus_events_t {
    UP = 0x1,
    DOWN = 0x2,
    IKE_UPDATE = 0x3,
    CHILD_REKEY = 0x4,
};

extern enum_name_t *updown_bus_events_names;


/**
 * Listener which invokes the scripts on CHILD_SA up/down.
 */
struct updownv2_listener_t {

	/**
	 * Implements listener_t.
	 */
	listener_t listener;

    /**
     * Reload the settings
     */

    bool (*reload)(updownv2_listener_t *this);

	/**
	 * Destroy a updownv2_listener_t.
	 */
	void (*destroy)(updownv2_listener_t *this);
};

/**
 * Create a updownv2_listener instance.
 */
updownv2_listener_t *updownv2_listener_create(updownv2_handler_t *handler);

#endif /** updownv2_LISTENER_H_ @}*/
