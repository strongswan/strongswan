/**
 * @file stroke_configuration_t.h
 *
 * @brief Interface of stroke_configuration_t.
 *
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#ifndef STROKE_CONFIGURATION_H
#define STROKE_CONFIGURATION_H

#include <config/configuration.h>

/**
 * @brief A message sent over the unix socket.
 * 
 */
typedef struct stroke_msg_t stroke_msg_t;

struct stroke_msg_t {
	/* length of this message with all strings */
	u_int16_t length;
	/* type of the message */
	enum {
		/* initiate a connection */
		STR_INITIATE,
		/* install SPD entries for a connection */
		STR_INSTALL,
		/* add a connection */
		STR_ADD_CONN,
		/* delete a connection */
		STR_DEL_CONN,
		/* more to come */
	} type;
	union {
		/* data for STR_INITIATE, STR_INSTALL */
		struct {
			char *name;
		} initiate, install;
		/* data for STR_ADD_CONN */
		struct {
			char *name;
			struct {
				union {
					u_int16_t family;
					struct sockaddr saddr;
					struct sockaddr_in v4;
					struct sockaddr_in6 v6;
				} address;
				char *id;
				union {
					u_int16_t family;
					struct sockaddr saddr;
					struct sockaddr_in v4;
					struct sockaddr_in6 v6;
				} subnet;
				u_int8_t subnet_netbits;
			} me, other;
		} add_conn;
	};
	u_int8_t buffer[];
};


typedef struct stroke_configuration_t stroke_configuration_t;

/**
 * @brief A config backend which uses a unix socket.
 * 
 * Allows config manipulation (as whack in pluto). This config
 * is used by the ipsec_starter utility. This configuration 
 * implementation opens a socket at /var/run/charon.ctl and 
 * waits for input from ipsec starter.
 * 
 * @b Constructors:
 * - stroke_configuration_create()
 * 
 * @ingroup config
 */
struct stroke_configuration_t {

	/**
	 * Implements configuration_t interface
	 */
	configuration_t configuration_interface;
};

/**
 * @brief Creates an configuration with a unix socket interface.
 * 
 * @return stroke_configuration_t object
 * 
 * @ingroup config
 */
stroke_configuration_t *stroke_configuration_create();

#endif /*STROKE_CONFIGURATION_H*/
