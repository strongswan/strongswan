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
 * @defgroup xauth_manager xauth_manager
 * @{ @ingroup xauth
 */

#ifndef XAUTH_MANAGER_H_
#define XAUTH_MANAGER_H_

#include "xauth_provider.h"
#include "xauth_verifier.h"

typedef struct xauth_manager_t xauth_manager_t;

/**
 * An xauth_manager registers xauth_providers and xauth_verifiers.
 */
struct xauth_manager_t {

	/**
	 * Register an xauth_provider
	 *
	 * @param provider		xauth_provider to be registered
	 */
	void (*add_provider)(xauth_manager_t *this, xauth_provider_t *provider);

	/**
	 * Register an xauth_verifier
	 *
	 * @param verifier		xauth_verifier to be registered
	 */
	void (*add_verifier)(xauth_manager_t *this, xauth_verifier_t *verifier);

	/**
	 * Use registered providers to retrieve an XAUTH user secret
     * based on connection information.
	 *
	 * @param c				connection information
	 * @param secret		secret if found, chunk_empty otherwise
	 * @return				TRUE if a matching secret was found
	 */
	bool (*get_secret)(xauth_manager_t *this, connection_t *c, chunk_t *secret);

	/**
	 * Use registered verifiers to verify an XAUTH user secret 
	 * based on connection information
	 *
	 * @param c				connection information
	 * @param secret		secret to be compared
	 * @return				TRUE if secret matches
	 */
	bool (*verify_secret)(xauth_manager_t *this, connection_t *c, chunk_t secret);

	/**
	 * Destroy an xauth_verifier instance.
	 */
	void (*destroy)(xauth_manager_t *this);
};

/**
 * Create an xauth_manager instance.
 */
xauth_manager_t *xauth_manager_create();

#endif /** XAUTH_MANAGER_H_ @}*/

