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

#include "xauth_default_verifier.h"

typedef struct private_xauth_default_verifier_t private_xauth_default_verifier_t;

/**
 * private data of xauth_default_verifier
 */
struct private_xauth_default_verifier_t {

	/**
	 * public functions
	 */
	xauth_verifier_t public;
};

METHOD(xauth_verifier_t, verify_secret, bool,
	private_xauth_default_verifier_t *this, connection_t *c, chunk_t secret)
{
	identification_t *user, *server;
	chunk_t xauth_secret;
	bool success = FALSE;

	server = c->spd.this.id;
	user = (c->xauth_identity) ? c->xauth_identity : c->spd.that.id;

	if (get_xauth_secret(user, server, &xauth_secret))
	{
		success = chunk_equals(secret, xauth_secret);

		if (!success && secret.len && secret.ptr[secret.len - 1] == 0)
		{	/* fix for null-terminated passwords (e.g. from Android 4) */
			secret.len--;
			success = chunk_equals(secret, xauth_secret);
		}

		chunk_clear(&xauth_secret);
	}
	return success;
}

METHOD(xauth_verifier_t, destroy, void,
	private_xauth_default_verifier_t *this)
{
	free(this);
}


/*
 * Described in header.
 */
xauth_verifier_t *xauth_default_verifier_create()
{
	private_xauth_default_verifier_t *this;

	INIT(this,
		.public = {
			.verify_secret = _verify_secret,
			.destroy = _destroy,
		 }
	);

	return &this->public;
}

