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

#include <string.h>

#include "authenticator.h"

#include <sa/authenticators/rsa_authenticator.h>
#include <sa/authenticators/psk_authenticator.h>
#include <sa/authenticators/eap_authenticator.h>


ENUM_BEGIN(auth_method_names, AUTH_RSA, AUTH_DSS,
	"RSA signature",
	"pre-shared key",
	"DSS signature");
ENUM_NEXT(auth_method_names, AUTH_EAP, AUTH_EAP, AUTH_DSS,
	"EAP");
ENUM_END(auth_method_names, AUTH_EAP);

/*
 * Described in header.
 */
authenticator_t *authenticator_create(ike_sa_t *ike_sa, auth_method_t auth_method)
{
	switch (auth_method)
	{
		case AUTH_RSA:
			return (authenticator_t*)rsa_authenticator_create(ike_sa);
		case AUTH_PSK:
			return (authenticator_t*)psk_authenticator_create(ike_sa);
		case AUTH_EAP:
			return (authenticator_t*)eap_authenticator_create(ike_sa);
		default:
			return NULL;
	}
}
