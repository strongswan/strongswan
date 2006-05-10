/**
 * @file stroke.h
 *
 * @brief Interface of stroke_t.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#ifndef STROKE_INTERFACE_H_
#define STROKE_INTERFACE_H_

#include <config/policies/policy_store.h>
#include <config/connections/connection_store.h>
#include <config/credentials/credential_store.h>


typedef struct stroke_t stroke_t;

/**
 * @brief Stroke is a configuration and control interface which
 * allows other processes to modify charons behavior.
 * 
 * stroke_t allows config manipulation (as whack in pluto). 
 * Messages of type stroke_msg_t's are sent over a unix socket
 * (/var/run/charon.ctl). stroke_t implements the connections_t
 * and the policies_t interface, which means it acts as a 
 * configuration backend for those too. stroke_t uses an own
 * thread to read from the socket.
 * 
 * @warning DO NOT cast stroke_t to any of the implemented interfaces!
 * stroke_t implements multiple interfaces, so you must use
 * stroke_t.interface_xy to access the specific interface! You have
 * been warned...
 * 
 * @todo Add clean thread cancellation
 * 
 * @b Constructors:
 * - stroke_create()
 * 
 * @ingroup threads
 */
struct stroke_t {
	
	/**
	 * @brief Destroy a stroke_t instance.
	 * 
	 * @param this		stroke_t objec to destroy
	 */
	void (*destroy) (stroke_t *this);
};


/**
 * @brief Create the stroke interface and listen on the socket.
 * 
 * @return stroke_t object
 * 
 * @ingroup threads
 */
stroke_t *stroke_create(void);

#endif /* STROKE_INTERFACE_H_ */
