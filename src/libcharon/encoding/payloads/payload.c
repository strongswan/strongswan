/*
 * Copyright (C) 2007 Tobias Brunner
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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


#include "payload.h"

#include <encoding/payloads/ike_header.h>
#include <encoding/payloads/sa_payload.h>

#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/cert_payload.h>
#include <encoding/payloads/certreq_payload.h>
#include <encoding/payloads/encryption_payload.h>
#include <encoding/payloads/ts_payload.h>
#include <encoding/payloads/delete_payload.h>
#include <encoding/payloads/vendor_id_payload.h>
#include <encoding/payloads/cp_payload.h>
#include <encoding/payloads/configuration_attribute.h>
#include <encoding/payloads/eap_payload.h>
#include <encoding/payloads/hash_payload.h>
#include <encoding/payloads/fragment_payload.h>
#include <encoding/payloads/unknown_payload.h>

ENUM_BEGIN(payload_type_names, NO_PAYLOAD, NO_PAYLOAD,
	"NO_PAYLOAD");
ENUM_NEXT(payload_type_names, SECURITY_ASSOCIATION_V1, CONFIGURATION_V1, NO_PAYLOAD,
	"SECURITY_ASSOCIATION_V1",
	"PROPOSAL_V1",
	"TRANSFORM_V1",
	"KEY_EXCHANGE_V1",
	"ID_V1",
	"CERTIFICATE_V1",
	"CERTIFICATE_REQUEST_V1",
	"HASH_V1",
	"SIGNATURE_V1",
	"NONCE_V1",
	"NOTIFY_V1",
	"DELETE_V1",
	"VENDOR_ID_V1",
	"CONFIGURATION_V1");
ENUM_NEXT(payload_type_names, NAT_D_V1, NAT_OA_V1, CONFIGURATION_V1,
	"NAT_D_V1",
	"NAT_OA_V1");
ENUM_NEXT(payload_type_names, SECURITY_ASSOCIATION, GENERIC_SECURE_PASSWORD_METHOD, NAT_OA_V1,
	"SECURITY_ASSOCIATION",
	"KEY_EXCHANGE",
	"ID_INITIATOR",
	"ID_RESPONDER",
	"CERTIFICATE",
	"CERTIFICATE_REQUEST",
	"AUTHENTICATION",
	"NONCE",
	"NOTIFY",
	"DELETE",
	"VENDOR_ID",
	"TRAFFIC_SELECTOR_INITIATOR",
	"TRAFFIC_SELECTOR_RESPONDER",
	"ENCRYPTED",
	"CONFIGURATION",
	"EXTENSIBLE_AUTHENTICATION",
	"GENERIC_SECURE_PASSWORD_METHOD");
#ifdef ME
ENUM_NEXT(payload_type_names, ID_PEER, ID_PEER, GENERIC_SECURE_PASSWORD_METHOD,
	"ID_PEER");
ENUM_NEXT(payload_type_names, NAT_D_DRAFT_00_03_V1, FRAGMENT_V1, ID_PEER,
	"NAT_D_DRAFT_V1",
	"NAT_OA_DRAFT_V1",
	"FRAGMENT");
#else
ENUM_NEXT(payload_type_names, NAT_D_DRAFT_00_03_V1, FRAGMENT_V1, GENERIC_SECURE_PASSWORD_METHOD,
	"NAT_D_DRAFT_V1",
	"NAT_OA_DRAFT_V1",
	"FRAGMENT");
#endif /* ME */
ENUM_NEXT(payload_type_names, HEADER, ENCRYPTED_V1, FRAGMENT_V1,
	"HEADER",
	"PROPOSAL_SUBSTRUCTURE",
	"PROPOSAL_SUBSTRUCTURE_V1",
	"TRANSFORM_SUBSTRUCTURE",
	"TRANSFORM_SUBSTRUCTURE_V1",
	"TRANSFORM_ATTRIBUTE",
	"TRANSFORM_ATTRIBUTE_V1",
	"TRAFFIC_SELECTOR_SUBSTRUCTURE",
	"CONFIGURATION_ATTRIBUTE",
	"CONFIGURATION_ATTRIBUTE_V1",
	"ENCRYPTED_V1");
ENUM_END(payload_type_names, ENCRYPTED_V1);

/* short forms of payload names */
ENUM_BEGIN(payload_type_short_names, NO_PAYLOAD, NO_PAYLOAD,
	"--");
ENUM_NEXT(payload_type_short_names, SECURITY_ASSOCIATION_V1, CONFIGURATION_V1, NO_PAYLOAD,
	"SA",
	"PROP",
	"TRANS",
	"KE",
	"ID",
	"CERT",
	"CERTREQ",
	"HASH",
	"SIG",
	"No",
	"N",
	"D",
	"V",
	"CP");
ENUM_NEXT(payload_type_short_names, NAT_D_V1, NAT_OA_V1, CONFIGURATION_V1,
	"NAT-D",
	"NAT-OA");
ENUM_NEXT(payload_type_short_names, SECURITY_ASSOCIATION, GENERIC_SECURE_PASSWORD_METHOD, NAT_OA_V1,
	"SA",
	"KE",
	"IDi",
	"IDr",
	"CERT",
	"CERTREQ",
	"AUTH",
	"No",
	"N",
	"D",
	"V",
	"TSi",
	"TSr",
	"E",
	"CP",
	"EAP",
	"GSPM");
#ifdef ME
ENUM_NEXT(payload_type_short_names, ID_PEER, ID_PEER, GENERIC_SECURE_PASSWORD_METHOD,
	"IDp");
ENUM_NEXT(payload_type_short_names, NAT_D_DRAFT_00_03_V1, FRAGMENT_V1, ID_PEER,
	"NAT-D",
	"NAT-OA",
	"FRAG");
#else
ENUM_NEXT(payload_type_short_names, NAT_D_DRAFT_00_03_V1, FRAGMENT_V1, GENERIC_SECURE_PASSWORD_METHOD,
	"NAT-D",
	"NAT-OA",
	"FRAG");
#endif /* ME */
ENUM_NEXT(payload_type_short_names, HEADER, ENCRYPTED_V1, FRAGMENT_V1,
	"HDR",
	"PROP",
	"PROP",
	"TRANS",
	"TRANS",
	"TRANSATTR",
	"TRANSATTR",
	"TSSUB",
	"CATTR",
	"CATTR",
	"E");
ENUM_END(payload_type_short_names, ENCRYPTED_V1);

/*
 * see header
 */
payload_t *payload_create(payload_type_t type)
{
	switch (type)
	{
		case HEADER:
			return (payload_t*)ike_header_create();
		case SECURITY_ASSOCIATION:
		case SECURITY_ASSOCIATION_V1:
			return (payload_t*)sa_payload_create(type);
		case PROPOSAL_SUBSTRUCTURE:
		case PROPOSAL_SUBSTRUCTURE_V1:
			return (payload_t*)proposal_substructure_create(type);
		case TRANSFORM_SUBSTRUCTURE:
		case TRANSFORM_SUBSTRUCTURE_V1:
			return (payload_t*)transform_substructure_create(type);
		case TRANSFORM_ATTRIBUTE:
		case TRANSFORM_ATTRIBUTE_V1:
			return (payload_t*)transform_attribute_create(type);
		case NONCE:
		case NONCE_V1:
			return (payload_t*)nonce_payload_create(type);
		case ID_INITIATOR:
		case ID_RESPONDER:
		case ID_V1:
		case NAT_OA_V1:
		case NAT_OA_DRAFT_00_03_V1:
#ifdef ME
		case ID_PEER:
#endif /* ME */
			return (payload_t*)id_payload_create(type);
		case AUTHENTICATION:
			return (payload_t*)auth_payload_create();
		case CERTIFICATE:
		case CERTIFICATE_V1:
			return (payload_t*)cert_payload_create(type);
		case CERTIFICATE_REQUEST:
		case CERTIFICATE_REQUEST_V1:
			return (payload_t*)certreq_payload_create(type);
		case TRAFFIC_SELECTOR_SUBSTRUCTURE:
			return (payload_t*)traffic_selector_substructure_create();
		case TRAFFIC_SELECTOR_INITIATOR:
			return (payload_t*)ts_payload_create(TRUE);
		case TRAFFIC_SELECTOR_RESPONDER:
			return (payload_t*)ts_payload_create(FALSE);
		case KEY_EXCHANGE:
		case KEY_EXCHANGE_V1:
			return (payload_t*)ke_payload_create(type);
		case NOTIFY:
		case NOTIFY_V1:
			return (payload_t*)notify_payload_create(type);
		case DELETE:
		case DELETE_V1:
			return (payload_t*)delete_payload_create(type, 0);
		case VENDOR_ID:
		case VENDOR_ID_V1:
			return (payload_t*)vendor_id_payload_create(type);
		case HASH_V1:
		case SIGNATURE_V1:
		case NAT_D_V1:
		case NAT_D_DRAFT_00_03_V1:
			return (payload_t*)hash_payload_create(type);
		case CONFIGURATION:
		case CONFIGURATION_V1:
			return (payload_t*)cp_payload_create(type);
		case CONFIGURATION_ATTRIBUTE:
		case CONFIGURATION_ATTRIBUTE_V1:
			return (payload_t*)configuration_attribute_create(type);
		case EXTENSIBLE_AUTHENTICATION:
			return (payload_t*)eap_payload_create();
		case ENCRYPTED:
		case ENCRYPTED_V1:
			return (payload_t*)encryption_payload_create(type);
		case FRAGMENT_V1:
			return (payload_t*)fragment_payload_create();
		default:
			return (payload_t*)unknown_payload_create(type);
	}
}

/**
 * See header.
 */
bool payload_is_known(payload_type_t type)
{
	if (type == HEADER)
	{
		return TRUE;
	}
	if (type >= SECURITY_ASSOCIATION && type <= EXTENSIBLE_AUTHENTICATION)
	{
		return TRUE;
	}
	if (type >= SECURITY_ASSOCIATION_V1 && type <= CONFIGURATION_V1)
	{
		return TRUE;
	}
	if (type >= NAT_D_V1 && type <= NAT_OA_V1)
	{
		return TRUE;
	}
#ifdef ME
	if (type == ID_PEER)
	{
		return TRUE;
	}
#endif
	if (type >= NAT_D_DRAFT_00_03_V1 && type <= FRAGMENT_V1)
	{
		return TRUE;
	}
	return FALSE;
}

/**
 * See header.
 */
void* payload_get_field(payload_t *payload, encoding_type_t type, u_int skip)
{
	encoding_rule_t *rule;
	int i, count;

	count = payload->get_encoding_rules(payload, &rule);
	for (i = 0; i < count; i++)
	{
		if (rule[i].type == type && skip-- == 0)
		{
			return ((char*)payload) + rule[i].offset;
		}
	}
	return NULL;
}
