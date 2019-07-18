/*
 * Copyright (C) 2019 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup tls_session tls_session
 * @{ @ingroup libtls
 */

#ifndef TLS_SESSION_H_
#define TLS_SESSION_H_

#include "tls.h"

typedef struct tls_session_t tls_session_t;

/**
 * TLS client session object
 */
struct tls_session_t {

	/**
	 * Read data from TLS session.
	 *
	 * @param buf		buffer to write received data to
	 * @param len		size of buffer
	 * @return			number of bytes read, 0 on EOF, -1 on error
	 */
	ssize_t (*read)(tls_session_t *this, void *buf, size_t len);

	/**
	 * Write data to a TLS session
	 *
	 * @param buf		data to send
	 * @param len		number of bytes to write from buf
	 * @return			TRUE if all bytes have been written
	 */
	bool (*write)(tls_session_t *this, void *buf, size_t len);

	/**
	 * Destroy a tls_session_t.
	 */
	void (*destroy)(tls_session_t *this);
};


/**
 * Create a tls_session instance.
 *
 * @param host_t			server IP address and TCP port
 * @param server_id			server identity
 * @param client_id			client identity, NULL for no client authentication
 * @param max_version		maximum TLS version to negotiate
 * @return					TLS client session
 */
tls_session_t *tls_session_create(host_t *host, identification_t *server_id,
												identification_t *client_id,
												tls_version_t max_version);

#endif /** TLS_SESSION_H_ @}*/