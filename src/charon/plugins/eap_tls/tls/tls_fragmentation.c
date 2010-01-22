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

#include "tls_fragmentation.h"

#include <daemon.h>

typedef struct private_tls_fragmentation_t private_tls_fragmentation_t;

/**
 * Private data of an tls_fragmentation_t object.
 */
struct private_tls_fragmentation_t {

	/**
	 * Public tls_fragmentation_t interface.
	 */
	tls_fragmentation_t public;
};

METHOD(tls_fragmentation_t, process, status_t,
	private_tls_fragmentation_t *this, tls_content_type_t type, chunk_t data)
{
	return NEED_MORE;
}

METHOD(tls_fragmentation_t, build, status_t,
	private_tls_fragmentation_t *this, tls_content_type_t *type, chunk_t *data)
{
	return INVALID_STATE;
}

METHOD(tls_fragmentation_t, destroy, void,
	private_tls_fragmentation_t *this)
{
	free(this);
}

/**
 * See header
 */
tls_fragmentation_t *tls_fragmentation_create()
{
	private_tls_fragmentation_t *this;

	INIT(this,
		.public = {
			.process = _process,
			.build = _build,
			.destroy = _destroy,
		},
	);

	return &this->public;
}
