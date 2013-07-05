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
 * @defgroup tls_stream tls_stream
 * @{ @ingroup tls
 */

#ifndef TLS_STREAM_H_
#define TLS_STREAM_H_

#include <library.h>
#include <tls_cache.h>

/**
 * Helper function to parse a tcp+tls:// URI.
 *
 * @param uri			URI to parse
 * @param addr			sockaddr, large enough for URI address
 * @param server		pointer receiving allocated server identity
 * @return				len of created addr, -1 on error
 */
int tls_stream_parse_uri(char *uri, struct sockaddr *addr,
						 identification_t **server);

/**
 * Helper function to create a stream from an FD and a server identity.
 *
 * @param fd			file descripter
 * @param is_server		TRUE to act as TLS server, FALSE for client
 * @param server		server identity, gets cloned
 * @param cache			shared TLS session cache, if any
 * @return				client stream, NULL on error
 */
stream_t *tls_stream_create_from_fd(int fd, bool is_server,
									identification_t *server,
									tls_cache_t *cache);

/**
 * Create a tls_stream instance.
 *
 * The following URIs are currently accepted by this constructor:
 * - tcp+tls://serverid@address:port
 *   Server authenticates with a certificate for serverid, no client auth.
 *
 * @param uri			URI to create a stream for
 * @return				stream instance, NULL on error
 */
stream_t *tls_stream_create(char *uri);

#endif /** TLS_STREAM_H_ @}*/
