/**
 * @file payload.h
 * 
 * @brief Interface payload_t.
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

#ifndef PAYLOAD_H_
#define PAYLOAD_H_

#include <types.h>
#include <definitions.h>
#include <encoding/payloads/encodings.h>


typedef enum payload_type_t payload_type_t;

/**
 * @brief Payload-Types of a IKEv2-Message.
 * 
 * Header and substructures are also defined as 
 * payload types with values from PRIVATE USE space.
 * 
 * @ingroup payloads
 */
enum payload_type_t{

	/**
	 * End of payload list in next_payload
	 */
	NO_PAYLOAD = 0,
	
	/**
	 * The security association (SA) payload containing proposals.
	 */
	SECURITY_ASSOCIATION = 33,

	/**
	 * The key exchange (KE) payload containing diffie-hellman values.
	 */
	KEY_EXCHANGE = 34,

	/**
	 * Identification for the original initiator (IDi).
	 */
	ID_INITIATOR = 35,

	/**
	 * Identification for the original responder (IDr).
	 */
	ID_RESPONDER = 36,

	/**
	 * Certificate payload with certificates (CERT).
	 */
	CERTIFICATE = 37,

	/**
	 * Certificate request payload (CERTREQ).
	 */
	CERTIFICATE_REQUEST = 38,

	/**
	 * Authentication payload contains auth data (AUTH).
	 */
	AUTHENTICATION = 39,

	/**
	 * Nonces, for initator and responder (Ni, Nr, N)
	 */
	NONCE = 40,

	/**
	 * Notif paylaod (N).
	 */
	NOTIFY = 41,

	/**
	 * Delete payload (D)
	 */
	DELETE = 42,

	/**
	 * Vendor id paylpoad (V).
	 */
	VENDOR_ID = 43,

	/**
	 * Traffic selector for the original initiator (TSi).
	 */
	TRAFFIC_SELECTOR_INITIATOR = 44,

	/**
	 * Traffic selector for the original responser (TSr).
	 */
	TRAFFIC_SELECTOR_RESPONDER = 45,

	/**
	 * Encryption payload, contains other payloads (E).
	 */
	ENCRYPTED = 46,

	/**
	 * Configuration payload (CP).
	 */
	CONFIGURATION = 47,

	/**
	 * Extensible authentication payload (EAP).
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


/**
 * String mappings for payload_type_t.
 */
extern mapping_t payload_type_m[];

/**
 * Special string mappings for payload_type_t in a short form.
 */
extern mapping_t payload_type_short_m[];


typedef struct payload_t payload_t;

/**
 * @brief Generic interface for all payload types (incl.header and substructures).
 * 
 * To handle all kinds of payloads on a generic way, this interface must
 * be implemented by every payload. This allows parser_t/generator_t a simple
 * handling of all payloads.
 * 
 * @b Constructors:
 * - payload_create() with the payload to instantiate.
 * 
 * @ingroup payloads
 */
struct payload_t {
	
	/**
	 * @brief Get encoding rules for this payload.
	 *
	 * @param this 				calling object
	 * @param[out] rules		location to store pointer of first rule
	 * @param[out] rule_count	location to store number of rules
	 */
	void (*get_encoding_rules) (payload_t *this, encoding_rule_t **rules, size_t *rule_count);

	/**
	 * @brief Get type of payload.
	 *
	 * @param this 				calling object
	 * @return 					type of this payload
	 */
	payload_type_t (*get_type) (payload_t *this);

	/**
	 * @brief Get type of next payload or NO_PAYLOAD (0) if this is the last one.
	 *
	 * @param this 				calling object
	 * @return 					type of next payload
	 */
	payload_type_t (*get_next_type) (payload_t *this);
	
	/**
	 * @brief Set type of next payload.
	 *
	 * @param this 				calling object
	 * @param type 				type of next payload
	 */
	void (*set_next_type) (payload_t *this,payload_type_t type);

	/**
	 * @brief Get length of payload.
	 *
	 * @param this 				calling object
	 * @return 					length of this payload
	 */
	size_t (*get_length) (payload_t *this);
	
	/**
	 * @brief Verifies payload structure and makes consistence check.
	 *
	 * @param this 				calling object
	 * @return 					
	 *							- SUCCESS
	 * 							- FAILED if consistence not given
	 */
	status_t (*verify) (payload_t *this);
	
	/**
	 * @brief Destroys a payload and all included substructures.
	 *
	 * @param this 				payload to destroy
	 */
	void (*destroy) (payload_t *this);
};

/**
 * @brief Create an empty payload.
 * 
 * Useful for the parser, who wants a generic constructor for all payloads.
 * It supports all payload_t methods. If a payload type is not known, 
 * an unknwon_paylod is created with the chunk of data in it.
 * 
 * @param type		type of the payload to create
 * @return			payload_t object
 */
payload_t *payload_create(payload_type_t type);

#endif /*PAYLOAD_H_*/
