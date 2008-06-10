/*
 * Copyright (C) 2008 Tobias Brunner
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
 * @defgroup pubkey_authenticator pubkey_authenticator
 * @{ @ingroup authenticators
 */

#ifndef PUBKEY_AUTHENTICATOR_H_
#define PUBKEY_AUTHENTICATOR_H_

typedef struct pubkey_authenticator_t pubkey_authenticator_t;

#include <sa/authenticators/authenticator.h>

/**
 * Implementation of the authenticator_t interface using AUTH_PUBKEY.
 */
struct pubkey_authenticator_t {

	/**
	 * Implemented authenticator_t interface.
	 */
	authenticator_t authenticator_interface;
};

/**
 * Creates an authenticator for AUTH_PUBKEY.
 *
 * @param ike_sa		associated ike_sa
 * @return				pubkey_authenticator_t object
 */
pubkey_authenticator_t *pubkey_authenticator_create(ike_sa_t *ike_sa);

#endif /* PUBKEY_AUTHENTICATOR_H_ @} */
