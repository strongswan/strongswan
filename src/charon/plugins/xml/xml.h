/*
 * Copyright (C) 2007-2008 Martin Willi
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
 * @defgroup xml xml
 * @ingroup cplugins
 *
 * @defgroup xml_i xml
 * @{ @ingroup xml
 */

#ifndef XML_H_
#define XML_H_

#include <plugins/plugin.h>

typedef struct xml_t xml_t;

/**
 * XML configuration and control interface.
 *
 * The XML interface uses a socket and a to communicate. The syntax is strict
 * XML, defined in the schema.xml specification.
 */
struct xml_t {

	/**
	 * implements the plugin interface.
	 */
	plugin_t plugin;
};

/**
 * Create a xml plugin instance.
 */
plugin_t *plugin_create();

#endif /* XML_H_ @}*/
