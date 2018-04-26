/*
 * Copyright (C) 2018 Sophos Group plc
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
 * @defgroup windows_dns_handler windows_dns_handler
 * @{ @ingroup windows_dns
 */

#ifndef WINDOWS_DNS_HANDLER_H_
#define WINDOWS_DNS_HANDLER_H_

#include <attributes/attribute_handler.h>

typedef struct windows_dns_handler_t windows_dns_handler_t;

/**
 * Windows specific DNS attribute handler.
 */
struct windows_dns_handler_t {

	/**
	 * Implements attribute_handler_t.
	 */
	attribute_handler_t handler;

	/**
	 * Destroy a windows_dns_handler_t.
	 */
	void (*destroy)(windows_dns_handler_t *this);
};

/**
 * Create an windows_dns_handler_t instance.
 */
windows_dns_handler_t *windows_dns_handler_create();

#endif /** WINDOWS_DNS_HANDLER_H_ @}*/
