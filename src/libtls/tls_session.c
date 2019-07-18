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

#include "tls_session.h"
#include "tls_socket.h"

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#define TLS_SESSION_NO_FD	-1

typedef struct private_tls_session_t private_tls_session_t;

/**
 * Private data of an tls_session_t object.
 */
struct private_tls_session_t {

	/**
	 * Public tls_session_t interface.
	 */
	tls_session_t public;

	/**
	 * TLS socket
	 */
	tls_socket_t *tls;

	/**
	 * Underlying OS socket
	 */
	int fd;
};

METHOD(tls_session_t, read_, ssize_t,
	private_tls_session_t *this, void *buf, size_t len)
{
	return this->tls->read(this->tls, buf, len, TRUE);
}

METHOD(tls_session_t, write_, bool,
	private_tls_session_t *this, void *buf, size_t len)
{
	return this->tls->write(this->tls, buf, len) != len;
}

METHOD(tls_session_t, destroy, void,
	private_tls_session_t *this)
{
	DESTROY_IF(this->tls);

	if (this->fd != TLS_SESSION_NO_FD)
	{
		close(this->fd);
	}
	free(this);
}

/**
 * See header
 */
tls_session_t *tls_session_create(host_t *host, identification_t *server_id,
												identification_t *client_id,
												tls_version_t max_version)
{
	private_tls_session_t *this;

	INIT(this,
		.public = {
			.read = _read_,
			.write = _write_,
			.destroy = _destroy,
		},
		.fd = TLS_SESSION_NO_FD,
	);

	/* open TCP socket */
	this->fd = socket(host->get_family(host), SOCK_STREAM, 0);
	if (this->fd == TLS_SESSION_NO_FD)
	{
		DBG1(DBG_TLS, "opening socket failed: %s", strerror(errno));
		destroy(this);
		return NULL;
	}

	if (connect(this->fd, host->get_sockaddr(host),
				*host->get_sockaddr_len(host)) == -1)
	{
		DBG1(DBG_TLS, "connecting to %#H failed: %s", host, strerror(errno));
		destroy(this);
		return NULL;
	}

	this->tls = tls_socket_create(FALSE, server_id, client_id, this->fd,
								  NULL, max_version, FALSE);
	if (!this->tls)
	{
		DBG1(DBG_TLS, "creating TLS socket failed");
		destroy(this);
		return NULL;
	}

	return &this->public;
}
