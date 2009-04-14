/*
 * Copyright (C) 2006-2009 Martin Willi
 * Copyright (C) 2008 Tobias Brunner
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
#include <encoding/payloads/auth_payload.h>


ENUM_BEGIN(auth_method_names, AUTH_RSA, AUTH_DSS,
	"RSA signature",
	"pre-shared key",
	"DSS signature");
ENUM_NEXT(auth_method_names, AUTH_ECDSA_256, AUTH_ECDSA_521, AUTH_DSS,
	"ECDSA-256 signature",
	"ECDSA-384 signature",
	"ECDSA-521 signature");
ENUM_END(auth_method_names, AUTH_ECDSA_521);

ENUM(auth_class_names, AUTH_CLASS_ANY, AUTH_CLASS_EAP,
	"any",
	"public key",
	"pre-shared key",
	"EAP",
);

/**
 * Described in header.
 */
authenticator_t *authenticator_create_builder(
									ike_sa_t *ike_sa, auth_cfg_t *cfg,
									chunk_t received_nonce, chunk_t sent_init)
{
	switch ((uintptr_t)cfg->get(cfg, AUTH_RULE_AUTH_CLASS))
	{
		case AUTH_CLASS_ANY:
			/* defaults to PUBKEY */
		case AUTH_CLASS_PUBKEY:
			return (authenticator_t*)pubkey_authenticator_create_builder(ike_sa,
											received_nonce, sent_init);
		case AUTH_CLASS_PSK:
			return (authenticator_t*)psk_authenticator_create_builder(ike_sa,
											received_nonce, sent_init);
		case AUTH_CLASS_EAP:
			return (authenticator_t*)eap_authenticator_create_builder(ike_sa,
											received_nonce, sent_init);
		default:
			return NULL;
	}
}

/**
 * Described in header.
 */
authenticator_t *authenticator_create_verifier(
									ike_sa_t *ike_sa, message_t *message,
									chunk_t sent_nonce, chunk_t received_init)
{
	auth_payload_t *auth_payload;
	
	auth_payload = (auth_payload_t*)message->get_payload(message, AUTHENTICATION);
	if (auth_payload == NULL)
	{
		return (authenticator_t*)eap_authenticator_create_verifier(ike_sa,
													sent_nonce, received_init);
	}
	switch (auth_payload->get_auth_method(auth_payload))
	{
		case AUTH_RSA:
		case AUTH_ECDSA_256:
		case AUTH_ECDSA_384:
		case AUTH_ECDSA_521:
			return (authenticator_t*)pubkey_authenticator_create_verifier(ike_sa,
													sent_nonce, received_init);
		case AUTH_PSK:
			return (authenticator_t*)psk_authenticator_create_verifier(ike_sa,
													sent_nonce, received_init);
		default:
			return NULL;
	}
}

