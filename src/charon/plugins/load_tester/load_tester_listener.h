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
 * @defgroup load_tester_listener_t load_tester_listener
 * @{ @ingroup load_tester
 */

#ifndef LOAD_TESTER_LISTENER_H_
#define LOAD_TESTER_LISTENER_H_

#include <bus/bus.h>

typedef struct load_tester_listener_t load_tester_listener_t;

/**
 * Provide hard-coded credentials for load testing.
 */
struct load_tester_listener_t {

	/**
	 * Implements listener set interface.
	 */
	listener_t listener;
	
	/**
	 * Destroy the backend.
	 */
	void (*destroy)(load_tester_listener_t *this);	
};

/**
 * Create a listener to handle special events during load test
 *
 * @return			listener
 */
load_tester_listener_t *load_tester_listener_create();

#endif /* LOAD_TESTER_LISTENER_H_ @}*/
