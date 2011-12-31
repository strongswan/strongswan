/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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
 * @defgroup tls_socket tls_socket
 * @{ @ingroup libtls
 */

#ifndef TLS_SOCKET_H_
#define TLS_SOCKET_H_

#include "tls.h"

typedef struct tls_socket_t tls_socket_t;

/**
 * TLS secured socket.
 *
 * Wraps a blocking (socket) file descriptor for a reliable transport into a
 * TLS secured socket. TLS negotiation happens on demand, certificates and
 * private keys are fetched from any registered credential set.
 */
struct tls_socket_t {

	/**
	 * Read data from secured socket, return allocated chunk.
	 *
	 * This call is blocking, you may use select() on the underlying socket to
	 * wait for data. If the there was non-application data available, the
	 * read function can return an empty chunk.
	 *
	 * @param data		pointer to allocate received data
	 * @return			TRUE if data received successfully
	 */
	bool (*read)(tls_socket_t *this, chunk_t *data);

	/**
	 * Write a chunk of data over the secured socket.
	 *
	 * @param data		data to send
	 * @return			TRUE if data sent successfully
	 */
	bool (*write)(tls_socket_t *this, chunk_t data);

	/**
	 * Read/write plain data from file descriptor.
	 *
	 * This call is blocking, but a thread cancellation point. Data is
	 * exchanged until one of the sockets gets closed or an error occurs.
	 *
	 * @param rfd		file descriptor to read plain data from
	 * @param wfd		file descriptor to write plain data to
	 * @return			TRUE if data exchanged successfully
	 */
	bool (*splice)(tls_socket_t *this, int rfd, int wfd);

	/**
	 * Get the underlying file descriptor passed to the constructor.
	 *
	 * @return			file descriptor
	 */
	int (*get_fd)(tls_socket_t *this);

	/**
	 * Destroy a tls_socket_t.
	 */
	void (*destroy)(tls_socket_t *this);
};

/**
 * Create a tls_socket instance.
 *
 * @param is_server			TRUE to act as TLS server
 * @param server			server identity
 * @param peer				client identity, NULL for no client authentication
 * @param fd				socket to read/write from
 * @param cache				session cache to use, or NULL
 * @return					TLS socket wrapper
 */
tls_socket_t *tls_socket_create(bool is_server, identification_t *server,
							identification_t *peer, int fd, tls_cache_t *cache);

#endif /** TLS_SOCKET_H_ @}*/
