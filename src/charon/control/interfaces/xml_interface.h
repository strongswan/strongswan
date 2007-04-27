/**
 * @file xml_interface.h
 *
 * @brief Interface of xml_interface_t.
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

#ifndef XML_INTERFACE_H_
#define XML_INTERFACE_H_

typedef struct xml_interface_t xml_interface_t;

#include <control/interfaces/interface.h>

/**
 * @brief The XML interface uses a socket to communicate using XML.
 * 
 * @b Constructors:
 * - xml_interface_create()
 * 
 * @ingroup interfaces
 */
struct xml_interface_t {
	
	/**
	 * implements interface_t.
	 */
	interface_t interface;
};


/**
 * @brief Create the XML interface.
 *
 * @return 			stroke_t object
 * 
 * @ingroup interfaces
 */
interface_t *interface_create(void);

#endif /* XML_INTERFACE_H_ */

