/*
 * Copyright (C) 2006-2007 Tobias Brunner
 * Copyright (C) 2005-2009 Martin Willi
 * Copyright (C) 2006 Daniel Roethlisberger
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
 * @defgroup message message
 * @{ @ingroup encoding
 */

#ifndef MESSAGE_H_
#define MESSAGE_H_

typedef struct message_t message_t;

#include <library.h>
#include <sa/ike_sa_id.h>
#include <network/packet.h>
#include <encoding/payloads/ike_header.h>
#include <encoding/payloads/notify_payload.h>
#include <utils/linked_list.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>

/**
 * This class is used to represent an IKEv2-Message.
 *
 * The message handles parsing and generation of payloads
 * via parser_t/generator_t. Encryption is done transparently
 * via the encryption_payload_t. A set of rules for messages
 * and payloads does check parsed messages.
 */
struct message_t {

	/**
	 * Sets the IKE major version of the message.
	 *
	 * @param major_version	major version to set
	 */
	void (*set_major_version) (message_t *this,u_int8_t major_version);

	/**
	 * Gets the IKE major version of the message.
	 *
	 * @return				major version of the message
	 */
	u_int8_t (*get_major_version) (message_t *this);
	
	/**
	 * Sets the IKE minor version of the message.
	 *
	 * @param minor_version	minor version to set
	 */
	void (*set_minor_version) (message_t *this,u_int8_t minor_version);

	/**
	 * Gets the IKE minor version of the message.
	 *
	 * @return				minor version of the message
	 */
	u_int8_t (*get_minor_version) (message_t *this);

	/**
	 * Sets the Message ID of the message.
	 *
	 * @param message_id	message_id to set
	 */
	void (*set_message_id) (message_t *this,u_int32_t message_id);

	/**
	 * Gets the Message ID of the message.
	 *
	 * @return				message_id type of the message
	 */
	u_int32_t (*get_message_id) (message_t *this);
	
	/**
	 * Gets the initiator SPI of the message.
	 *
	 * @return				initiator spi of the message
	 */
	u_int64_t (*get_initiator_spi) (message_t *this);

	/**
	 * Gets the responder SPI of the message.
	 *
	 * @return				responder spi of the message
	 */
	u_int64_t (*get_responder_spi) (message_t *this);

	/**
	 * Sets the IKE_SA ID of the message.
	 * 
	 * ike_sa_id gets cloned.
	 *
	 * @param ike_sa_id		ike_sa_id to set
	 */
	void (*set_ike_sa_id) (message_t *this, ike_sa_id_t * ike_sa_id);

	/**
	 * Gets the IKE_SA ID of the message.
	 *
	 * The ike_sa_id points to the message internal id, do not modify.
	 *
	 * @return				ike_sa_id of message
	 */
	ike_sa_id_t *(*get_ike_sa_id) (message_t *this);

	/**
	 * Sets the exchange type of the message.
	 *
	 * @param exchange_type	exchange_type to set
	 */
	void (*set_exchange_type) (message_t *this,exchange_type_t exchange_type);

	/**
	 * Gets the exchange type of the message.
	 *
	 * @return				exchange type of the message
	 */
	exchange_type_t (*get_exchange_type) (message_t *this);
	
	/**
	 * Gets the payload type of the first payload.
	 * 
	 * @return				payload type of the first payload
	 */
	payload_type_t (*get_first_payload_type) (message_t *this);

	/**
	 * Sets the request flag.
	 *
	 * @param request		TRUE if message is a request, FALSE if it is a reply
	 */
	void (*set_request) (message_t *this, bool request);

	/**
	 * Gets request flag.
	 *
	 * @return				TRUE if message is a request, FALSE if it is a reply
	 */
	bool (*get_request) (message_t *this);

	/**
	 * Append a payload to the message.
	 * 
	 * If the payload must be encrypted is not specified here. Encryption
	 * of payloads is evaluated via internal rules for the messages and
	 * is done before generation. The order of payloads may change, since
	 * all payloads to encrypt are added to the encryption payload, which is 
	 * always the last one.
	 *
	 * @param payload 		payload to append
	 */	
	void (*add_payload) (message_t *this, payload_t *payload);

	/**
	 * Build a notify payload and add it to the message.
	 * 
	 * This is a helper method to create notify messages or add
	 * notify payload to messages. The flush parameter specifies if existing
	 * payloads should get removed before appending the notify.
	 *
	 * @param flush			TRUE to remove existing payloads
	 * @param type			type of the notify
	 * @param data			a chunk of data to add to the notify, gets cloned
	 */	
	void (*add_notify) (message_t *this, bool flush, notify_type_t type, 
						chunk_t data);

	/**
	 * Parses header of message.
	 * 
	 * Begins parisng of a message created via message_create_from_packet().
	 * The parsing context is stored, so a subsequent call to parse_body()
	 * will continue the parsing process.
	 *
	 * @return
	 * 					- SUCCESS if header could be parsed
	 *					- PARSE_ERROR if corrupted/invalid data found
	 * 					- FAILED if consistence check of header failed
	 */
	status_t (*parse_header) (message_t *this);
	
	/**
	 * Parses body of message.
	 * 
	 * The body gets not only parsed, but rather it gets verified. 
	 * All payloads are verified if they are allowed to exist in the message 
	 * of this type and if their own structure is ok. 
	 * If there are encrypted payloads, they get decrypted via the supplied 
	 * crypter. Also the message integrity gets verified with the supplied
	 * signer.
	 * Crypter/signer can be omitted (by passing NULL) when no encryption 
	 * payload is expected.
	 *
	 * @param crypter	crypter to decrypt encryption payloads
	 * @param signer	signer to verifiy a message with an encryption payload
	 * @return
	 * 					- SUCCESS if parsing successful
	 * 					- NOT_SUPPORTED if ciritcal unknown payloads found
	 * 					- NOT_SUPPORTED if message type is not supported!
	 *					- PARSE_ERROR if message parsing failed
	 * 					- VERIFY_ERROR if message verification failed (bad syntax)
	 * 					- FAILED if integrity check failed
	 * 					- INVALID_STATE if crypter/signer not supplied, but needed
	 */
	status_t (*parse_body) (message_t *this, crypter_t *crypter, signer_t *signer);

	/**
	 * Generates the UDP packet of specific message.
	 * 
	 * Payloads which must be encrypted are generated first and added to
	 * an encryption payload. This encryption payload will get encrypted via 
	 * the supplied crypter. Then all other payloads and the header get generated.
	 * After that, the checksum is added to the encryption payload over the full 
	 * message.
	 * Crypter/signer can be omitted (by passing NULL) when no encryption 
	 * payload is expected.
	 * Generation is only done once, multiple calls will just return a packet copy.
	 *
	 * @param crypter	crypter to use when a payload must be encrypted
	 * @param signer	signer to build a mac
	 * @param packet	copy of generated packet
	 * @return
	 * 					- SUCCESS if packet could be generated
	 * 					- INVALID_STATE if exchange type is currently not set
	 * 					- NOT_FOUND if no rules found for message generation
	 * 					- INVALID_STATE if crypter/signer not supplied but needed.
	 */	
	status_t (*generate) (message_t *this, crypter_t *crypter, signer_t *signer, packet_t **packet);

	/**
	 * Gets the source host informations. 
	 * 
	 * @warning Returned host_t object is not getting cloned, 
	 * do not destroy nor modify.
	 *
	 * @return			host_t object representing source host
	 */	
	host_t * (*get_source) (message_t *this);
	
	/**
	 * Sets the source host informations. 
	 * 
	 * @warning host_t object is not getting cloned and gets destroyed by
	 * 			message_t.destroy or next call of message_t.set_source.
	 *
	 * @param host		host_t object representing source host
	 */	
	void (*set_source) (message_t *this, host_t *host);

	/**
	 * Gets the destination host informations. 
	 * 
	 * @warning Returned host_t object is not getting cloned, 
	 * do not destroy nor modify.
	 *
	 * @return			host_t object representing destination host
	 */	
	host_t * (*get_destination) (message_t *this);

	/**
	 * Sets the destination host informations. 
	 * 
	 * @warning host_t object is not getting cloned and gets destroyed by
	 * 			message_t.destroy or next call of message_t.set_destination.
	 *
	 * @param host		host_t object representing destination host
	 */	
	void (*set_destination) (message_t *this, host_t *host);
	
	/**
	 * Create an enumerator over all payloads.
	 *
	 * @return			enumerator over payload_t
	 */	
	enumerator_t * (*create_payload_enumerator) (message_t *this);
	
	/**
	 * Find a payload of a specific type.
	 * 
	 * Returns the first occurance. 
	 *
	 * @param type		type of the payload to find
	 * @return			payload, or NULL if no such payload found
	 */	
	payload_t* (*get_payload) (message_t *this, payload_type_t type);
	
	/**
	 * Get the first notify payload of a specific type.
	 *
	 * @param type		type of notification payload
	 * @return			notify payload, NULL if no such notify found
	 */
	notify_payload_t* (*get_notify)(message_t *this, notify_type_t type);
	
	/**
	 * Returns a clone of the internal stored packet_t object.
	 *
	 * @return			packet_t object as clone of internal one
	 */	
	packet_t * (*get_packet) (message_t *this);
	
	/**
	 * Returns a clone of the internal stored packet_t data.
	 *
	 * @return			clone of the internal stored packet_t data.
	 */	
	chunk_t (*get_packet_data) (message_t *this);
	
	/**
	 * Destroys a message and all including objects.
	 */
	void (*destroy) (message_t *this);
};

/**
 * Creates an message_t object from a incoming UDP Packet.
 * 
 * @warning the given packet_t object is not copied and gets 
 *			destroyed in message_t's destroy call.
 * 
 * - exchange_type is set to NOT_SET
 * - original_initiator is set to TRUE
 * - is_request is set to TRUE
 * Call message_t.parse_header afterwards.
 * 
 * @param packet		packet_t object which is assigned to message	
 * @return 				message_t object
 */
message_t * message_create_from_packet(packet_t *packet);


/**
 * Creates an empty message_t object.
 *
 * - exchange_type is set to NOT_SET
 * - original_initiator is set to TRUE
 * - is_request is set to TRUE
 * 
 * @return message_t object
 */
message_t * message_create(void);

#endif /** MESSAGE_H_ @}*/
