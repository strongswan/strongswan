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

#include <string.h>

#include "authenticator.h"

#include <sa/authenticators/pubkey_authenticator.h>
#include <sa/authenticators/psk_authenticator.h>
#include <sa/authenticators/eap_authenticator.h>


ENUM_BEGIN(auth_method_names, AUTH_RSA, AUTH_DSS,
	"RSA signature",
	"pre-shared key",
	"DSS signature");
ENUM_NEXT(auth_method_names, AUTH_ECDSA_256, AUTH_ECDSA_521, AUTH_DSS,
	"ECDSA-256 signature",
	"ECDSA-384 signature",
	"ECDSA-521 signature");
ENUM_NEXT(auth_method_names, AUTH_EAP, AUTH_EAP, AUTH_ECDSA_521,
	"EAP");
ENUM_END(auth_method_names, AUTH_EAP);

/**
 * Described in header.
 */
authenticator_t *authenticator_create(ike_sa_t *ike_sa, config_auth_method_t auth_method)
{
	switch (auth_method)
	{
		case CONF_AUTH_PUBKEY:
			return (authenticator_t*)pubkey_authenticator_create(ike_sa);
		case CONF_AUTH_PSK:
			return (authenticator_t*)psk_authenticator_create(ike_sa);
		case CONF_AUTH_EAP:
			return (authenticator_t*)eap_authenticator_create(ike_sa);
		default:
			return NULL;
	}
}

/**
 * Described in header.
 */
authenticator_t *authenticator_create_from_auth_payload(ike_sa_t *ike_sa, auth_payload_t *auth_payload)
{
	switch (auth_payload->get_auth_method(auth_payload))
	{
		case AUTH_RSA:
		case AUTH_ECDSA_256:
		case AUTH_ECDSA_384:
		case AUTH_ECDSA_521:
			return (authenticator_t*)pubkey_authenticator_create(ike_sa);
		case AUTH_PSK:
			return (authenticator_t*)psk_authenticator_create(ike_sa);
		default:
			return NULL;
	}
}
