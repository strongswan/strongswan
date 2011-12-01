/*
 * Copyright (C) 2006-2009 Martin Willi
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
 * @defgroup xauth_authenticator xauth_authenticator
 * @{ @ingroup authenticators
 */

#ifndef XAUTH_AUTHENTICATOR_H_
#define XAUTH_AUTHENTICATOR_H_

typedef struct xauth_authenticator_t xauth_authenticator_t;

#include <sa/authenticators/authenticator.h>

/**
 * Implementation of authenticator_t using XAuth.
 */
struct xauth_authenticator_t {

	/**
	 * Implemented authenticator_t interface.
	 */
	authenticator_t authenticator;
};

/**
 * Create an authenticator to build XAuth response payloads.
 *
 * @param ike_sa			associated ike_sa
 * @return					PSK authenticator
 */
xauth_authenticator_t *xauth_authenticator_create_builder(ike_sa_t *ike_sa);

/**
 * Create an authenticator to verify using XAuth payloads.
 *
 * @param ike_sa			associated ike_sa
 * @return					PSK authenticator
 */
xauth_authenticator_t *xauth_authenticator_create_verifier(ike_sa_t *ike_sa);

#endif /** XAUTH_AUTHENTICATOR_H_ @}*/
