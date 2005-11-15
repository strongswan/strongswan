/**
 * @file payload.c
 * 
 * @brief Generic payload interface
 * 
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include "ike_header.h"
#include "sa_payload.h"
#include "nonce_payload.h"





/*
 * build the mappings for payload_type_t
 */
mapping_t payload_type_t_mappings[] = {
	{NO_PAYLOAD, "NO_PAYLOAD"},
	{SECURITY_ASSOCIATION, "SECURITY_ASSOCIATION"},
	{KEY_EXCHANGE, "KEY_EXCHANGE"},
	{ID_INITIATOR, "ID_INITIATOR"},
	{ID_RESPONDER, "ID_RESPONDER"},
	{CERTIFICATE, "CERTIFICATE"},
	{CERTIFICATE_REQUEST, "CERTIFICATE_REQUEST"},
	{AUTHENTICATION, "AUTHENTICATION"},
	{NONCE, "NONCE"},
	{NOTIFY, "NOTIFY"},
	{DELETE, "DELETE"},
	{VENDOR_ID, "VENDOR_ID"},
	{TRAFFIC_SELECTOR_INITIATOR, "TRAFFIC_SELECTOR_INITIATOR"},
	{TRAFFIC_SELECTOR_RESPONDER, "TRAFFIC_SELECTOR_RESPONDER"},
	{ENCRYPTED, "ENCRYPTED"},
	{CONFIGURATION, "CONFIGURATION"},
	{EXTENSIBLE_AUTHENTICATION, "EXTENSIBLE_AUTHENTICATION"},
	{HEADER, "HEADER"},
	{PROPOSAL_SUBSTRUCTURE, "PROPOSAL_SUBSTRUCTURE"},
	{TRANSFORM_SUBSTRUCTURE, "TRANSFORM_SUBSTRUCTURE"},
	{TRANSFORM_ATTRIBUTE, "TRANSFORM_ATTRIBUTE"},
	{MAPPING_END, NULL}
};

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
		default:
			return NULL;
	}
}

