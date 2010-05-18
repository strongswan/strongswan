/*
 * Copyright (C) 2010 Andreas Steffen
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

#include <keys.h>

#include "xauth_default_provider.h"

typedef struct private_xauth_default_provider_t private_xauth_default_provider_t;

/**
 * private data of xauth_default_provider
 */
struct private_xauth_default_provider_t {

	/**
	 * public functions
	 */
	xauth_provider_t public;
};

METHOD(xauth_provider_t, get_secret, bool,
	private_xauth_default_provider_t *this, connection_t *c, chunk_t *secret)
{
	identification_t *user, *server;

	server = c->spd.that.id;
	user = (c->xauth_identity) ? c->xauth_identity : c->spd.this.id;

	return get_xauth_secret(user, server, secret);
}

METHOD(xauth_provider_t, destroy, void,
	private_xauth_default_provider_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
xauth_provider_t *xauth_default_provider_create()
{
	private_xauth_default_provider_t *this;

	INIT(this,
		.public = {
			.get_secret = _get_secret,
			.destroy = _destroy,
		 }
	);

	return &this->public;
}

