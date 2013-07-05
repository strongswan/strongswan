/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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
 * @defgroup tls_stream_service tls_stream_service
 * @{ @ingroup tls
 */

#ifndef TLS_STREAM_SERVICE_H_
#define TLS_STREAM_SERVICE_H_

#include <library.h>

/**
 * Create a service instance for TLS secured TCP sockets.
 *
 * @param uri		TLS socket specific URI, must start with "tcp+tls://"
 * @param backlog	size of the backlog queue, as passed to listen()
 * @return			stream_service instance, NULL on failure
 */
stream_service_t* tls_stream_service_create(char *uri, int backlog);

#endif /** TLS_STREAM_SERVICE_H_ @}*/
