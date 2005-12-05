/**
 * @file payload.h
 * 
 * @brief Generic payload interface.
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

#ifndef PAYLOAD_H_
#define PAYLOAD_H_

#include <types.h>
#include <definitions.h>
#include <encoding/payloads/encodings.h>


typedef enum payload_type_t payload_type_t;

/**
 * Payload-Types of a IKEv2-Message.
 * 
 * 
 * Header and substructures are also defined as 
 * payload types with values from PRIVATE USE space.
 * 
 * @ingroup payloads
 */
enum payload_type_t{

	/**
	 * NO_PAYLOAD
	 */
	NO_PAYLOAD = 0,
	
	/**
	 * SA
	 */
	SECURITY_ASSOCIATION = 33,

	/**
	 * KE
	 */
	KEY_EXCHANGE = 34,

	/**
	 * IDi
	 */
	ID_INITIATOR = 35,

	/**
	 * IDr
	 */
	ID_RESPONDER = 36,

	/**
	 * CERT
	 */
	CERTIFICATE = 37,

	/**
	 * CERTREQ
	 */
	CERTIFICATE_REQUEST = 38,

	/**
	 * AUTH
	 */
	AUTHENTICATION = 39,

	/**
	 * Ni, Nr
	 */
	NONCE = 40,

	/**
	 * N
	 */
	NOTIFY = 41,

	/**
	 * D
	 */
	DELETE = 42,

	/**
	 * V
	 */
	VENDOR_ID = 43,

	/**
	 * TSi
	 */
	TRAFFIC_SELECTOR_INITIATOR = 44,

	/**
	 * TSr
	 */
	TRAFFIC_SELECTOR_RESPONDER = 45,

	/**
	 * E
	 */
	ENCRYPTED = 46,

	/**
	 * CP
	 */
	CONFIGURATION = 47,

	/**
	 * EAP
	 */
	EXTENSIBLE_AUTHENTICATION = 48,
	
	/**
	 * Header has a value of PRIVATE USE space.
	 * 
	 * This payload type is not send over wire and just 
	 * used internally to handle IKEv2-Header like a payload.
	 */
	HEADER = 140,
	
	/**
	 * PROPOSAL_SUBSTRUCTURE has a value of PRIVATE USE space.
	 * 
	 * This payload type is not send over wire and just 
	 * used internally to handle a proposal substructure like a payload.
	 */
	PROPOSAL_SUBSTRUCTURE = 141,

	/**
	 * TRANSFORM_SUBSTRUCTURE has a value of PRIVATE USE space.
	 * 
	 * This payload type is not send over wire and just 
	 * used internally to handle a transform substructure like a payload.
	 */
	TRANSFORM_SUBSTRUCTURE = 142,
	
	/**
	 * TRANSFORM_ATTRIBUTE has a value of PRIVATE USE space.
	 * 
	 * This payload type is not send over wire and just 
	 * used internally to handle a transform attribute like a payload.
	 */
	TRANSFORM_ATTRIBUTE = 143,

	/**
	 * TRAFFIC_SELECTOR_SUBSTRUCTURE has a value of PRIVATE USE space.
	 * 
	 * This payload type is not send over wire and just 
	 * used internally to handle a transform selector like a payload.
	 */	
	TRAFFIC_SELECTOR_SUBSTRUCTURE = 144,
	
	/**
	 * CONFIGURATION_ATTRIBUTE has a value of PRIVATE USE space.
	 * 
	 * This payload type is not send over wire and just 
	 * used internally to handle a transform attribute like a payload.
	 */
	CONFIGURATION_ATTRIBUTE = 145,
	
	/**
	 * A unknown payload has a value of PRIVATE USE space.
	 * 
	 * This payload type is not send over wire and just 
	 * used internally to handle a unknown payload.
	 */
	UNKNOWN_PAYLOAD = 146,
};


/*
 * Build string mapping array for payload_type_t.
 */
extern mapping_t payload_type_m[];


typedef struct payload_t payload_t;

/**
 * @brief Generic interface for all payload types (inclusive 
 * header and substructures).
 * 
 * @ingroup payloads
 */
struct payload_t {
	/**
	 * @brief Destroys a payload and all included substructures.
	 *
	 * @param this 	payload to destroy
	 */
	void (*destroy) (payload_t *this);
	
	/**
	 * @brief Get encoding rules for this payload
	 *
	 * @param this 				calling object
	 * @param[out] rules		location to store pointer of first rule
	 * @param[out] rule_count	location to store number of rules
	 */
	void (*get_encoding_rules) (payload_t *this, encoding_rule_t **rules, size_t *rule_count);

	/**
	 * @brief get type of payload
	 *
	 * @param this 				calling object
	 * @return 					type of this payload
	 */
	payload_type_t (*get_type) (payload_t *this);

	/**
	 * @brief get type of next payload or zero if this is the last one
	 *
	 * @param this 				calling object
	 * @return 					type of next payload
	 */
	payload_type_t (*get_next_type) (payload_t *this);
	
	/**
	 * @brief set type of next payload
	 *
	 * @param this 				calling object
	 * @param type 				type of next payload
	 */
	void (*set_next_type) (payload_t *this,payload_type_t type);

	/**
	 * @brief get length of payload 
	 *
	 * @param this 				calling object
	 * @return 					length of this payload
	 */
	size_t (*get_length) (payload_t *this);
	
	/**
	 * @brief Verifies payload structure and makes consistence check
	 *
	 * @param this 				calling object
	 * @return 					
	 *							- SUCCESS
	 * 							- FAILED if consistence not given
	 */
	status_t (*verify) (payload_t *this);
};

/**
 * @brief Create an empty payload.
 * 
 * Useful for the parser, who wants a generic constructor for all payloads.
 * It supports all payload_t methods.
 * 
 * @param type		type of the payload to create
 * @return			created payload
 */
 
payload_t *payload_create(payload_type_t type);

#endif /*PAYLOAD_H_*/
