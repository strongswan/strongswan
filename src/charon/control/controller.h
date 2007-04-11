/**
 * @file controller.h
 *
 * @brief Interface of controller_t.
 *
 */

/*
 * Copyright (C) 2007 Martin Willi
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

#ifndef CONTROLLER_H_
#define CONTROLLER_H_

typedef struct controller_t controller_t;

#include <config/backends/local_backend.h>

/**
 * @brief controller is a configuration and control interface which
 * allows other processes to modify charons behavior.
 * 
 * controller_t allows config manipulation (as whack in pluto). Configurations
 * are stored in a special backend, the in-memory local_backend_t.
 * Messages of type controller_msg_t's are sent over a unix socket
 * (/var/run/charon.ctl).
 * 
 * @b Constructors:
 * - controller_create()
 * 
 * @ingroup control
 */
struct controller_t {
	
	/**
	 * @brief Destroy a controller_t instance.
	 * 
	 * @param this		controller_t objec to destroy
	 */
	void (*destroy) (controller_t *this);
};


/**
 * @brief Create a controller instance.
 * 
 * @return 			controller_t object
 * 
 * @ingroup control
 */
controller_t *controller_create();

#endif /* CONTROLLER_H_ */
