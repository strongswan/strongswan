/**
 * @file host.h
 *
 * @brief host object, identifies a host and defines some useful functions on it.
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

#ifndef HOST_H_
#define HOST_H_

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../types.h"

/**
 * @brief The logger object
 */
typedef struct host_s host_t;
struct host_s {
	status_t (*clone) (host_t *this, host_t **other);
	sockaddr_t  *(*get_sockaddr) (host_t *this);
	socklen_t *(*get_sockaddr_len) (host_t *this);
	status_t (*destroy) (host_t *this);
};

/**
 * @brief Constructor to create a logger_t object.
 *
 * @param logger_name 	Name for the logger_t object
 * @param log_level		or'ed set of log_levels to assign to the new logger_t object
 * @param output			FILE * if log has to go on a file output, NULL for syslog
 * @return 				logger_t object or NULL if failed
 */
host_t *host_create(int family, char *address, u_int16_t port);



#endif /*HOST_H_*/
