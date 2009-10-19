/*
 * Copyright (C) 2009 Martin Willi
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
 * @defgroup simaka_message simaka_message
 * @{ @ingroup libsimaka
 */

#ifndef SIMAKA_MESSAGE_H_
#define SIMAKA_MESSAGE_H_

#include <daemon.h>
#include <enum.h>

typedef struct simaka_message_t simaka_message_t;
typedef enum simaka_attribute_t simaka_attribute_t;
typedef enum simaka_subtype_t simaka_subtype_t;

/**
 * Subtypes of EAP-SIM/AKA messages
 */
enum simaka_subtype_t {
	AKA_CHALLENGE = 1,
	AKA_AUTHENTICATION_REJECT = 2,
	AKA_SYNCHRONIZATION_FAILURE = 4,
	AKA_IDENTITY = 5,
	SIM_START = 10,
	SIM_CHALLENGE = 11,
	SIM_NOTIFICATION = 12,
	AKA_NOTIFICATION = 12,
	SIM_REAUTHENTICATION = 13,
	AKA_REAUTHENTICATION = 13,
	SIM_CLIENT_ERROR = 14,
	AKA_CLIENT_ERROR = 14,
};

/**
 * Enum names for simaka_subtype_t
 */
extern enum_name_t *simaka_subtype_names;

/**
 * Attributes in EAP-SIM/AKA messages
 */
enum simaka_attribute_t {
	AT_RAND = 1,
	AT_AUTN = 2,
	AT_RES = 3,
	AT_AUTS = 4,
	AT_PADDING = 6,
	AT_NONCE_MT = 7,
	AT_PERMANENT_ID_REQ = 10,
	AT_MAC = 11,
	AT_NOTIFICATION = 12,
	AT_ANY_ID_REQ = 13,
	AT_IDENTITY = 14,
	AT_VERSION_LIST = 15,
	AT_SELECTED_VERSION = 16,
	AT_FULLAUTH_ID_REQ = 17,
	AT_COUNTER = 19,
	AT_COUNTER_TOO_SMALL = 20,
	AT_NONCE_S = 21,
	AT_CLIENT_ERROR_CODE = 22,
	AT_IV = 129,
	AT_ENCR_DATA = 130,
	AT_NEXT_PSEUDONYM = 132,
	AT_NEXT_REAUTH_ID = 133,
	AT_CHECKCODE = 134,
	AT_RESULT_IND = 135,
};

/**
 * Enum names for simaka_attribute_t
 */
extern enum_name_t *simaka_attribute_names;

/**
 * EAP-SIM and EAP-AKA message abstraction.
 *
 * Messages for EAP-SIM and EAP-AKA share a common format, this class
 * abstracts such a message and provides encoding/encryption/signing
 * functionality.
 */
struct simaka_message_t {

	/**
	 * Check if the given message is a request or response.
	 *
	 * @return			TRUE if request, FALSE if response
	 */
	bool (*is_request)(simaka_message_t *this);

	/**
	 * Get the EAP message identifier.
	 *
	 * @return			EAP message identifier
	 */
	u_int8_t (*get_identifier)(simaka_message_t *this);

	/**
	 * Get the EAP type of the message.
	 *
	 * @return			EAP type: EAP-SIM or EAP-AKA
	 */
	eap_type_t (*get_type)(simaka_message_t *this);

	/**
	 * Get the subtype of an EAP-SIM message.
	 *
	 * @return			subtype of message
	 */
	simaka_subtype_t (*get_subtype)(simaka_message_t *this);

	/**
	 * Create an enumerator over message attributes.
	 *
	 * @return			enumerator over (simaka_attribute_t, chunk_t)
	 */
	enumerator_t* (*create_attribute_enumerator)(simaka_message_t *this);

	/**
	 * Append an attribute to the EAP-SIM message.
	 *
	 * Make sure to pass only data of correct length for the given attribute.
	 *
	 * @param type		type of attribute to add to message
	 * @param data		unpadded attribute data to add
	 */
	void (*add_attribute)(simaka_message_t *this, simaka_attribute_t type,
						  chunk_t data);

	/**
	 * Parse a message, with optional attribute decryption.
	 *
	 * This method does not verify message integrity, as the key is available
	 * only after the payload has been parsed.
	 *
	 * @param crypter	crypter to decrypt AT_ENCR_DATA attribute
	 * @return			TRUE if message parsed successfully
	 */
	bool (*parse)(simaka_message_t *this, crypter_t *crypter);

	/**
	 * Verify the message integrity of a parsed message.
	 *
	 * @param signer	signer to verify AT_MAC attribute
	 * @param sigdata	additional data to include in signature, if any
	 * @return			TRUE if message integrity check successful
	 */
	bool (*verify)(simaka_message_t *this, signer_t *signer, chunk_t sigdata);

	/**
	 * Generate a message, optionally encrypt attributes and create a MAC.
	 *
	 * @param crypter	crypter to encrypt attributes requiring encryption
	 * @param rng		random number generator for IV
	 * @param signer	signer to create AT_MAC attribute
	 * @param sigdata	additional data to include in signature, if any
	 * @return			generated eap payload, NULL if failed
	 */
	eap_payload_t* (*generate)(simaka_message_t *this, crypter_t *crypter,
							   rng_t *rng, signer_t *signer, chunk_t sigdata);

	/**
	 * Destroy a simaka_message_t.
	 */
	void (*destroy)(simaka_message_t *this);
};

/**
 * Create an empty simaka_message.
 *
 * @param request		TRUE for a request message, FALSE for a response
 * @param identifier	EAP message identifier
 * @param type			EAP subtype of the message
 * @return				empty message of requested kind, NULL on error
 */
simaka_message_t *simaka_message_create(bool request, u_int8_t identifier,
								eap_type_t type, simaka_subtype_t subtype);

/**
 * Create an simaka_message from a chunk of data.
 *
 * @param payload		payload to create message from
 * @return				EAP message, NULL on error
 */
simaka_message_t *simaka_message_create_from_payload(eap_payload_t *payload);

#endif /* SIMAKA_MESSAGE_H_ @}*/
