/**
 * @file interface.h
 *
 * @brief Interface of interface_t.
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

#ifndef INTERFACE_H_
#define INTERFACE_H_

typedef struct interface_t interface_t;

/**
 * @brief Interface for a controller.
 *
 * An interface controls the daemon by calling functions on the
 * interface_manager. All interfaces are manager by the interface_manager
 * in a generic way, so they need their own class.
 * 
 * @b Constructors:
 * - interface_create() of one of the modules
 * 
 * @ingroup interfaces
 */
struct interface_t {
	
	/**
	 * @brief Destroy all interfaces
	 * 
	 * @param this		stroke_t objec to destroy
	 */
	void (*destroy) (interface_t *this);
};


/**
 * Constructor in a control interface module to create the interface.
 *
 * @ingroup interfaces
 */
typedef interface_t*(*interface_constructor_t)(void);

#endif /* INTERFACE_H_ */

