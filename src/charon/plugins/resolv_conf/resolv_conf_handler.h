/*
 * Copyright (C) 2009 Martin Willi
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

/**
 * @defgroup resolv_conf_handler resolv_conf_handler
 * @{ @ingroup resolv_conf
 */

#ifndef RESOLV_CONF_HANDLER_H_
#define RESOLV_CONF_HANDLER_H_

#include <config/attributes/attribute_handler.h>

typedef struct resolv_conf_handler_t resolv_conf_handler_t;

/**
 * Handle DNS configuration attributes by mangling a resolv.conf file.
 */
struct resolv_conf_handler_t {

	/**
	 * Implements the attribute_handler_t interface
	 */
	attribute_handler_t handler;

	/**
	 * Destroy a resolv_conf_handler_t.
	 */
	void (*destroy)(resolv_conf_handler_t *this);
};

/**
 * Create a resolv_conf_handler instance.
 */
resolv_conf_handler_t *resolv_conf_handler_create();

#endif /* RESOLV_CONF_HANDLER_ @}*/
