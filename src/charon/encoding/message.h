/**
 * @file message.h
 *
 * @brief Interface of message_t.
 *
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
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

#ifndef MESSAGE_H_
#define MESSAGE_H_

#include <types.h>
#include <sa/ike_sa_id.h>
#include <network/packet.h>
#include <encoding/payloads/ike_header.h>
#include <encoding/payloads/notify_payload.h>
#include <utils/linked_list.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>


typedef struct message_t message_t;

/**
 * @brief This class is used to represent an IKEv2-Message.
 *
 * The message handles parsing and generation of payloads
 * via parser_t/generator_t. Encryption is done transparently
 * via the encryption_payload_t. A set of rules for messages
 * and payloads does check parsed messages.
 * 
 * @b Constructors:
 * - message_create()
 * - message_create_from_packet()
 * - message_create_notify_reply()
 *
 * @ingroup encoding
 */
struct message_t {

	/**
	 * @brief Sets the IKE major version of the message.
	 *
	 * @param this 			message_t object
	 * @param major_version	major version to set
	 */
	void (*set_major_version) (message_t *this,u_int8_t major_version);

	/**
	 * @brief Gets the IKE major version of the message.
	 *
	 * @param this 			message_t object
	 * @return				major version of the message
	 */
	u_int8_t (*get_major_version) (message_t *this);
	
	/**
	 * @brief Sets the IKE minor version of the message.
	 *
	 * @param this 			message_t object
	 * @param minor_version	minor version to set
	 */
	void (*set_minor_version) (message_t *this,u_int8_t minor_version);

	/**
	 * @brief Gets the IKE minor version of the message.
	 *
	 * @param this 			message_t object
	 * @return				minor version of the message
	 */
	u_int8_t (*get_minor_version) (message_t *this);

	/**
	 * @brief Sets the Message ID of the message.
	 *
	 * @param this 			message_t object
	 * @param message_id		message_id to set
	 */
	void (*set_message_id) (message_t *this,u_int32_t message_id);

	/**
	 * @brief Gets the Message ID of the message.
	 *
	 * @param this 			message_t object
	 * @return				message_id type of the message
	 */
	u_int32_t (*get_message_id) (message_t *this);
	
	/**
	 * @brief Gets the initiator SPI of the message.
	 *
	 * @param this 			message_t object
	 * @return				initiator spi of the message
	 */
	u_int64_t (*get_initiator_spi) (message_t *this);

	/**
	 * @brief Gets the responder SPI of the message.
	 *
	 * @param this 			message_t object
	 * @return				responder spi of the message
	 */
	u_int64_t (*get_responder_spi) (message_t *this);

	/**
	 * @brief Sets the IKE_SA ID of the message.
	 * 
	 * ike_sa_id gets cloned.
	 *
	 * @param this 			message_t object
	 * @param ike_sa_id		ike_sa_id to set
	 */
	void (*set_ike_sa_id) (message_t *this, ike_sa_id_t * ike_sa_id);

	/**
	 * @brief Gets the IKE_SA ID of the message.
	 *
	 * The ike_sa_id points to the message internal id, do not modify.
	 *
	 * @param this 			message_t object
	 * @return				ike_sa_id of message
	 */
	ike_sa_id_t *(*get_ike_sa_id) (message_t *this);

	/**
	 * @brief Sets the exchange type of the message.
	 *
	 * @param this 			message_t object
	 * @param exchange_type	exchange_type to set
	 */
	void (*set_exchange_type) (message_t *this,exchange_type_t exchange_type);

	/**
	 * @brief Gets the exchange type of the message.
	 *
	 * @param this 			message_t object
	 * @return				exchange type of the message
	 */
	exchange_type_t (*get_exchange_type) (message_t *this);

	/**
	 * @brief Sets the request flag.
	 *
	 * @param this 					message_t object
	 * @param original_initiator		TRUE if message is a request, FALSE if it is a reply
	 */
	void (*set_request) (message_t *this,bool request);

	/**
	 * @brief Gets request flag.
	 *
	 * @param this 			message_t object
	 * @return				TRUE if message is a request, FALSE if it is a reply
	 */
	bool (*get_request) (message_t *this);

	/**
	 * @brief Append a payload to the message.
	 * 
	 * If the payload must be encrypted is not specified here. Encryption
	 * of payloads is evaluated via internal rules for the messages and
	 * is done before generation. The order of payloads may change, since
	 * all payloads to encrypt are added to the encryption payload, which is 
	 * always the last one.
	 *
	 * @param this 			message_t object
	 * @param payload 		payload to append
	 */	
	void (*add_payload) (message_t *this, payload_t *payload);

	/**
	 * @brief Parses header of message.
	 * 
	 * Begins parisng of a message created via message_create_from_packet().
	 * The parsing context is stored, so a subsequent call to parse_body()
	 * will continue the parsing process.
	 *
	 * @param this 		message_t object
	 * @return
	 * 					- SUCCESS if header could be parsed
	 *					- PARSE_ERROR if corrupted/invalid data found
	 * 					- FAILED if consistence check of header failed
	 */
	status_t (*parse_header) (message_t *this);
	
	/**
	 * @brief Parses body of message.
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
	 * @param this 		message_t object
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
	 * @brief Generates the UDP packet of specific message.
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
	 * @param this 		message_t object
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
	 * @brief Gets the source host informations. 
	 * 
	 * @warning Returned host_t object is not getting cloned, 
	 * do not destroy nor modify.
	 *
	 * @param this 		message_t object
	 * @return			host_t object representing source host
	 */	
	host_t * (*get_source) (message_t *this);
	
	/**
	 * @brief Sets the source host informations. 
	 * 
	 * @warning host_t object is not getting cloned and gets destroyed by
	 * 			message_t.destroy or next call of message_t.set_source.
	 *
	 * @param this 		message_t object
	 * @param host		host_t object representing source host
	 */	
	void (*set_source) (message_t *this, host_t *host);

	/**
	 * @brief Gets the destination host informations. 
	 * 
	 * @warning Returned host_t object is not getting cloned, 
	 * do not destroy nor modify.
	 *
	 * @param this 		message_t object
	 * @return			host_t object representing destination host
	 */	
	host_t * (*get_destination) (message_t *this);

	/**
	 * @brief Sets the destination host informations. 
	 * 
	 * @warning host_t object is not getting cloned and gets destroyed by
	 * 			message_t.destroy or next call of message_t.set_destination.
	 *
	 * @param this 		message_t object
	 * @param host		host_t object representing destination host
	 */	
	void (*set_destination) (message_t *this, host_t *host);
	
	/**
	 * @brief Returns an iterator on all stored payloads.
	 * 
	 * @warning Don't insert payloads over this iterator. 
	 * 			Use add_payload() instead.
	 *
	 * @param this 		message_t object
	 * @return			iterator_t object which has to get destroyd by the caller
	 */	
	iterator_t * (*get_payload_iterator) (message_t *this);
	
	/**
	 * @brief Returns a clone of the internal stored packet_t object.
	 *
	 * @param this 		message_t object
	 * @return			packet_t object as clone of internal one
	 */	
	packet_t * (*get_packet) (message_t *this);
	
	/**
	 * @brief Returns a clone of the internal stored packet_t data.
	 *
	 * @param this 		message_t object
	 * @return			clone of the internal stored packet_t data.
	 */	
	chunk_t (*get_packet_data) (message_t *this);
	
	/**
	 * @brief Destroys a message and all including objects.
	 *
	 * @param this 		message_t object
	 */
	void (*destroy) (message_t *this);
};

/**
 * @brief Creates an message_t object from a incoming UDP Packet.
 * 
 * @warning the given packet_t object is not copied and gets 
 *			destroyed in message_t's destroy call.
 * 
 * @warning Packet is not parsed in here!
 * 
 * - exchange_type is set to NOT_SET
 * - original_initiator is set to TRUE
 * - is_request is set to TRUE
 * Call message_t.parse_header afterwards.
 * 
 * @param packet		packet_t object which is assigned to message	
 * @return 				message_t object
 * 
 * @ingroup encoding
 */
message_t * message_create_from_packet(packet_t *packet);


/**
 * @brief Creates an empty message_t object.
 *
 * - exchange_type is set to NOT_SET
 * - original_initiator is set to TRUE
 * - is_request is set to TRUE
 * 
 * @return message_t object
 *
 * @ingroup encoding
 */
message_t * message_create(void);

#endif /*MESSAGE_H_*/
