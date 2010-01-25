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

#include "tls_peer.h"

#include <daemon.h>

#include <time.h>

typedef struct private_tls_peer_t private_tls_peer_t;

/**
 * Private data of an tls_peer_t object.
 */
struct private_tls_peer_t {

	/**
	 * Public tls_peer_t interface.
	 */
	tls_peer_t public;
};

METHOD(tls_handshake_t, process, status_t,
	private_tls_peer_t *this, tls_handshake_type_t type, chunk_t data)
{
	return NEED_MORE;
}

METHOD(tls_handshake_t, build, status_t,
	private_tls_peer_t *this, tls_handshake_type_t *type, chunk_t *data)
{
	return INVALID_STATE;
}

METHOD(tls_handshake_t, destroy, void,
	private_tls_peer_t *this)
{
	free(this);
}

/**
 * See header
 */
tls_peer_t *tls_peer_create()
{
	private_tls_peer_t *this;

	INIT(this,
		.public.handshake = {
			.process = _process,
			.build = _build,
			.destroy = _destroy,
		},
	);

	return &this->public;
}
