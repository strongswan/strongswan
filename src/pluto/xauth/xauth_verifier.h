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

/**
 * @defgroup xauth_verifier xauth_verifier
 * @{ @ingroup xauth
 */

#ifndef XAUTH_VERIFIER_H_
#define XAUTH_VERIFIER_H_

#include <library.h>

#include <connections.h>

typedef struct xauth_verifier_t xauth_verifier_t;

/**
 * An xauth verifier verifies xauth user secrets on the server side.
 */
struct xauth_verifier_t {

	/**
	 * Verify an XAUTH user secret base on connection information
	 *
	 * @param c				connection information
	 * @param secret		secret to be compared
	 * @return				TRUE if secret matches
	 */
	bool (*verify_secret)(xauth_verifier_t *this, connection_t *c, chunk_t secret);

	/**
	 * Destroy an xauth_verifier instance.
	 */
	void (*destroy)(xauth_verifier_t *this);
};

/**
 * Create an xauth_verifier instance.
 */
xauth_verifier_t *xauth_verifier_create();

#endif /** XAUTH_VERIFIER_H_ @}*/

