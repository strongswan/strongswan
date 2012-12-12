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

/**
 * @defgroup payload payload
 * @{ @ingroup payloads
 */

#ifndef PAYLOAD_H_
#define PAYLOAD_H_

typedef enum payload_type_t payload_type_t;
typedef struct payload_t payload_t;

#include <library.h>
#include <encoding/payloads/encodings.h>

/**
 * Domain of interpretation used by IPsec/IKEv1
 */
#define IKEV1_DOI_IPSEC 1

/**
 * Payload-Types of an IKE message.
 *
 * Header and substructures are also defined as
 * payload types with values from PRIVATE USE space.
 */
enum payload_type_t {

	/**
	 * End of payload list in next_payload
	 */
	NO_PAYLOAD = 0,

	/**
	 * The security association (SA) payload containing proposals.
	 */
	SECURITY_ASSOCIATION_V1 = 1,

	/**
	 * The proposal payload, containing transforms.
	 */
	PROPOSAL_V1 = 2,

	/**
	 * The transform payload.
	 */
	TRANSFORM_V1 = 3,

	/**
	 * The key exchange (KE) payload containing diffie-hellman values.
	 */
	KEY_EXCHANGE_V1 = 4,

	/**
	 * ID payload.
	 */
	ID_V1 = 5,

	/**
	 * Certificate payload with certificates (CERT).
	 */
	CERTIFICATE_V1 = 6,

	/**
	 * Certificate request payload.
	 */
	CERTIFICATE_REQUEST_V1 = 7,

	/**
	 * Hash payload.
	 */
	HASH_V1 = 8,

	/**
	 * Signature payload
	 */
	SIGNATURE_V1 = 9,

	/**
	 * Nonce payload.
	 */
	NONCE_V1 = 10,

	/**
	 * Notification payload.
	 */
	NOTIFY_V1 = 11,

	/**
	 * Delete payload.
	 */
	DELETE_V1 = 12,

	/**
	 * Vendor id payload.
	 */
	VENDOR_ID_V1 = 13,

	/**
	 * Attribute payload (ISAKMP Mode Config, aka configuration payload.
	 */
	CONFIGURATION_V1 = 14,

	/**
	 * NAT discovery payload (NAT-D).
	 */
	NAT_D_V1 = 20,

	/**
	 * NAT original address payload (NAT-OA).
	 */
	NAT_OA_V1 = 21,

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
	 * Nonces, for initiator and responder (Ni, Nr, N)
	 */
	NONCE = 40,

	/**
	 * Notify paylaod (N).
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
	 * Generic Secure Password Method (GSPM).
	 */
	GENERIC_SECURE_PASSWORD_METHOD = 49,

#ifdef ME
	/**
	 * Identification payload for peers has a value from
	 * the PRIVATE USE space.
	 */
	ID_PEER = 128,
#endif /* ME */

	/**
	 * NAT discovery payload (NAT-D) (drafts).
	 */
	NAT_D_DRAFT_00_03_V1 = 130,

	/**
	 * NAT original address payload (NAT-OA) (drafts).
	 */
	NAT_OA_DRAFT_00_03_V1 = 131,

	/**
	 * IKE fragment (proprietary IKEv1 extension)
	 */
	FRAGMENT_V1 = 132,

	/**
	 * Header has a value of PRIVATE USE space.
	 *
	 * This type and all the following are never sent over wire and are
	 * used internally only.
	 */
	HEADER = 256,

	/**
	 * PROPOSAL_SUBSTRUCTURE, IKEv2 proposals in a SA payload.
	 */
	PROPOSAL_SUBSTRUCTURE,

	/**
	 * PROPOSAL_SUBSTRUCTURE_V1, IKEv1 proposals in a SA payload.
	 */
	PROPOSAL_SUBSTRUCTURE_V1,

	/**
	 * TRANSFORM_SUBSTRUCTURE, IKEv2 transforms in a proposal substructure.
	 */
	TRANSFORM_SUBSTRUCTURE,

	/**
	 * TRANSFORM_SUBSTRUCTURE_V1, IKEv1 transforms in a proposal substructure.
	 */
	TRANSFORM_SUBSTRUCTURE_V1,

	/**
	 * TRANSFORM_ATTRIBUTE, IKEv2 attribute in a transform.
	 */
	TRANSFORM_ATTRIBUTE,

	/**
	 * TRANSFORM_ATTRIBUTE_V1, IKEv1 attribute in a transform.
	 */
	TRANSFORM_ATTRIBUTE_V1,

	/**
	 * TRAFFIC_SELECTOR_SUBSTRUCTURE, traffic selector in a TS payload.
	 */
	TRAFFIC_SELECTOR_SUBSTRUCTURE,

	/**
	 * CONFIGURATION_ATTRIBUTE, IKEv2 attribute in a configuration payload.
	 */
	CONFIGURATION_ATTRIBUTE,

	/**
	 * CONFIGURATION_ATTRIBUTE_V1, IKEv1 attribute in a configuration payload.
	 */
	CONFIGURATION_ATTRIBUTE_V1,

	/**
	 * This is not really a payload, but rather the complete IKEv1 message.
	 */
	ENCRYPTED_V1,
};

/**
 * enum names for payload_type_t.
 */
extern enum_name_t *payload_type_names;

/**
 * enum names for payload_type_t in a short form.
 */
extern enum_name_t *payload_type_short_names;

/**
 * Generic interface for all payload types (incl.header and substructures).
 *
 * To handle all kinds of payloads on a generic way, this interface must
 * be implemented by every payload. This allows parser_t/generator_t a simple
 * handling of all payloads.
 */
struct payload_t {

	/**
	 * Get encoding rules for this payload.
	 *
	 * @param rules			location to store pointer to rules
	 * @return				number of rules
	 */
	int (*get_encoding_rules) (payload_t *this, encoding_rule_t **rules);

	/**
	 * Get non-variable header length for a variable length payload.
	 *
	 * @return				fixed length of the payload
	 */
	int (*get_header_length)(payload_t *this);

	/**
	 * Get type of payload.
	 *
	 * @return				type of this payload
	 */
	payload_type_t (*get_type) (payload_t *this);

	/**
	 * Get type of next payload or NO_PAYLOAD (0) if this is the last one.
	 *
	 * @return				type of next payload
	 */
	payload_type_t (*get_next_type) (payload_t *this);

	/**
	 * Set type of next payload.
	 *
	 * @param type			type of next payload
	 */
	void (*set_next_type) (payload_t *this,payload_type_t type);

	/**
	 * Get length of payload.
	 *
	 * @return				length of this payload
	 */
	size_t (*get_length) (payload_t *this);

	/**
	 * Verifies payload structure and makes consistence check.
	 *
	 * @return				SUCCESS,  FAILED if consistence not given
	 */
	status_t (*verify) (payload_t *this);

	/**
	 * Destroys a payload and all included substructures.
	 */
	void (*destroy) (payload_t *this);
};

/**
 * Create an empty payload.
 *
 * Useful for the parser, who wants a generic constructor for all payloads.
 * It supports all payload_t methods. If a payload type is not known,
 * an unknwon_paylod is created with the chunk of data in it.
 *
 * @param type		type of the payload to create
 * @return			payload_t object
 */
payload_t *payload_create(payload_type_t type);

/**
 * Check if a specific payload is implemented, or handled as unknown payload.
 *
 * @param type		type of the payload to check
 * @return			FALSE if payload type handled as unknown payload
 */
bool payload_is_known(payload_type_t type);

/**
 * Get the value field in a payload using encoding rules.
 *
 * @param payload	payload to look up a field
 * @param type		encoding rule type to look up
 * @param skip		number rules of type to skip, 0 to get first
 * @return			type specific value pointer, NULL if not found
 */
void* payload_get_field(payload_t *payload, encoding_type_t type, u_int skip);

#endif /** PAYLOAD_H_ @}*/
