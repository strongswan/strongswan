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

#include "tls_protection.h"

#include <daemon.h>

typedef struct private_tls_protection_t private_tls_protection_t;

/**
 * Private data of an tls_protection_t object.
 */
struct private_tls_protection_t {

	/**
	 * Public tls_protection_t interface.
	 */
	tls_protection_t public;

	/**
	 * Upper layer, TLS record compression
	 */
	tls_compression_t *compression;
};

METHOD(tls_protection_t, process, status_t,
	private_tls_protection_t *this, tls_content_type_t type, chunk_t data)
{
	return this->compression->process(this->compression, type, data);
}

METHOD(tls_protection_t, build, status_t,
	private_tls_protection_t *this, tls_content_type_t *type, chunk_t *data)
{
	return this->compression->build(this->compression, type, data);
}

METHOD(tls_protection_t, destroy, void,
	private_tls_protection_t *this)
{
	free(this);
}

/**
 * See header
 */
tls_protection_t *tls_protection_create(tls_compression_t *compression)
{
	private_tls_protection_t *this;

	INIT(this,
		.public = {
			.process = _process,
			.build = _build,
			.destroy = _destroy,
		},
		.compression = compression,
	);

	return &this->public;
}
