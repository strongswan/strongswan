/**
 * @file stroke_interface.h
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

typedef struct stroke_interface_t stroke_interface_t;

#include <control/interfaces/interface.h>

/**
 * @brief Stroke is a configuration and control interface which
 * allows other processes to modify charons behavior.
 * 
 * stroke_t allows config manipulation (as whack in pluto). Configurations
 * are stored in a special backend, the in-memory local_backend_t.
 * Messages of type stroke_msg_t's are sent over a unix socket
 * (/var/run/charon.ctl).
 * 
 * @b Constructors:
 * - stroke_create()
 * 
 * @ingroup interfaces
 */
struct stroke_interface_t {
	
	/**
	 * implements interface_t.
	 */
	interface_t interface;
};


/**
 * @brief Create the stroke interface and listen on the socket.
 * 
 * @return 			stroke_t object
 * 
 * @ingroup interfaces
 */
interface_t *interface_create(void);

#endif /* STROKE_INTERFACE_H_ */

