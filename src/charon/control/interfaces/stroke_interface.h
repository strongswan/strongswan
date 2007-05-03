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
 * @brief Simple configuration interface using unix-sockets.
 * 
 * Stroke is a home-brewed communication interface inspired by whack. It
 * uses a unix socket (/var/run/charon.ctl).
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
 * @return 			interface_t for the stroke interface
 * 
 * @ingroup interfaces
 */
interface_t *interface_create(void);

#endif /* STROKE_INTERFACE_H_ */

