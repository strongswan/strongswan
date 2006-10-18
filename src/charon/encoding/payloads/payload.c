/**
 * @file payload.c
 * 
 * @brief Generic constructor to the payload_t interface.
 * 
 * 
 */

/*
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
#include <encoding/payloads/unknown_payload.h>


ENUM_BEGIN(payload_type_names, NO_PAYLOAD, NO_PAYLOAD,
	"NO_PAYLOAD");
ENUM_NEXT(payload_type_names, SECURITY_ASSOCIATION, EXTENSIBLE_AUTHENTICATION, NO_PAYLOAD,
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
	"EXTENSIBLE_AUTHENTICATION");
ENUM_NEXT(payload_type_names, HEADER, UNKNOWN_PAYLOAD, EXTENSIBLE_AUTHENTICATION,
	"HEADER",
	"PROPOSAL_SUBSTRUCTURE",
	"TRANSFORM_SUBSTRUCTURE",
	"TRANSFORM_ATTRIBUTE",
	"TRAFFIC_SELECTOR_SUBSTRUCTURE",
	"CONFIGURATION_ATTRIBUTE",
	"UNKNOWN_PAYLOAD");
ENUM_END(payload_type_names, UNKNOWN_PAYLOAD);

/* short forms of payload names */
ENUM_BEGIN(payload_type_short_names, NO_PAYLOAD, NO_PAYLOAD,
	"--");
ENUM_NEXT(payload_type_short_names, SECURITY_ASSOCIATION, EXTENSIBLE_AUTHENTICATION, NO_PAYLOAD,
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
	"EAP");
ENUM_NEXT(payload_type_short_names, HEADER, UNKNOWN_PAYLOAD, EXTENSIBLE_AUTHENTICATION,
	"HDR",
	"PROP",
	"TRANS",
	"TRANSATTR",
	"TSSUB",
	"CPATTR",
	"??");
ENUM_END(payload_type_short_names, UNKNOWN_PAYLOAD);

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
			return (payload_t*)sa_payload_create();
		case PROPOSAL_SUBSTRUCTURE:
			return (payload_t*)proposal_substructure_create();
		case TRANSFORM_SUBSTRUCTURE:
			return (payload_t*)transform_substructure_create();
		case TRANSFORM_ATTRIBUTE:
			return (payload_t*)transform_attribute_create();
		case NONCE:
			return (payload_t*)nonce_payload_create();
		case ID_INITIATOR:
			return (payload_t*)id_payload_create(TRUE);
		case ID_RESPONDER:
			return (payload_t*)id_payload_create(FALSE);
		case AUTHENTICATION:
			return (payload_t*)auth_payload_create();
		case CERTIFICATE:
			return (payload_t*)cert_payload_create();
		case CERTIFICATE_REQUEST:
			return (payload_t*)certreq_payload_create();
		case TRAFFIC_SELECTOR_SUBSTRUCTURE:
			return (payload_t*)traffic_selector_substructure_create();
		case TRAFFIC_SELECTOR_INITIATOR:
			return (payload_t*)ts_payload_create(TRUE);
		case TRAFFIC_SELECTOR_RESPONDER:
			return (payload_t*)ts_payload_create(FALSE);
		case KEY_EXCHANGE:
			return (payload_t*)ke_payload_create();
		case NOTIFY:
			return (payload_t*)notify_payload_create();
		case DELETE:
			return (payload_t*)delete_payload_create(0);
		case VENDOR_ID:
			return (payload_t*)vendor_id_payload_create();
		case CONFIGURATION:
			return (payload_t*)cp_payload_create();
		case CONFIGURATION_ATTRIBUTE:
			return (payload_t*)configuration_attribute_create();
		case EXTENSIBLE_AUTHENTICATION:
			return (payload_t*)eap_payload_create();
		case ENCRYPTED:
			return (payload_t*)encryption_payload_create();
		default:
			return (payload_t*)unknown_payload_create();
	}
}

