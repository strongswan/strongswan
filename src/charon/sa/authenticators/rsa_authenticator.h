/*
 * Copyright (C) 2006 Martin Willi
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
 *
 * $Id$
 */

/**
 * @defgroup rsa_authenticator rsa_authenticator
 * @{ @ingroup authenticators
 */

#ifndef RSA_AUTHENTICATOR_H_
#define RSA_AUTHENTICATOR_H_

typedef struct rsa_authenticator_t rsa_authenticator_t;

#include <sa/authenticators/authenticator.h>

/**
 * Implementation of the authenticator_t interface using AUTH_RSA.
 */
struct rsa_authenticator_t {

	/**
	 * Implemented authenticator_t interface.
	 */
	authenticator_t authenticator_interface;
};

/**
 * Creates an authenticator for AUTH_RSA.
 *
 * @param ike_sa		associated ike_sa
 * @return				rsa_authenticator_t object
 */
rsa_authenticator_t *rsa_authenticator_create(ike_sa_t *ike_sa);

#endif /* RSA_AUTHENTICATOR_H_ @} */
