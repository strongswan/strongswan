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
 * @defgroup xauth_provider xauth_provider
 * @{ @ingroup xauth
 */

#ifndef XAUTH_PROVIDER_H_
#define XAUTH_PROVIDER_H_

#include <library.h>

#include <connections.h>

typedef struct xauth_provider_t xauth_provider_t;

/**
 * An xauth provider retrieves xauth user secrets on the client side. 
 */
struct xauth_provider_t {

	/**
	 * Retrieve an XAUTH user secret based on connection information.
	 *
	 * @param c				connection information
	 * @param secret		secret if found, chunk_empty otherwise
	 * @return				TRUE if a matching secret was found
	 */
	bool (*get_secret)(xauth_provider_t *this, connection_t *c, chunk_t *secret);

	/**
	 * Destroy an xauth_provider instance.
	 */
	void (*destroy)(xauth_provider_t *this);
};

/**
 * Create an xauth_provider instance.
 */
xauth_provider_t *xauth_provider_create();

#endif /** XAUTH_PROVIDER_H_ @}*/

