/**
 * @file message.h
 *
 * @brief Interface of message_t.
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

#ifndef MESSAGE_H_
#define MESSAGE_H_

#include <types.h>
#include <sa/ike_sa_id.h>
#include <network/packet.h>
#include <encoding/payloads/ike_header.h>
#include <utils/linked_list.h>
#include <transforms/crypters/crypter.h>
#include <transforms/signers/signer.h>


typedef struct message_t message_t;

/**
 * @brief This class is used to represent an IKEv2-Message.
 *
 * An IKEv2-Message is either a request or response.
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
	 * @brief Gets the responder SPI of the message.
	 *
	 * @param this 			message_t object
	 * @return				responder spi of the message
	 */
	u_int64_t (*get_responder_spi) (message_t *this);

	/**
	 * @brief Sets the IKE_SA ID of the message.
	 * 
	 * @warning ike_sa_id gets cloned  internaly and 
	 * so can be destroyed afterwards.
	 *
	 * @param this 			message_t object
	 * @param ike_sa_id		ike_sa_id to set
	 */
	void (*set_ike_sa_id) (message_t *this,ike_sa_id_t * ike_sa_id);

	/**
	 * @brief Gets the IKE_SA ID of the message.
	 * 
	 * @warning The returned ike_sa_id is a clone of the internal one.
	 * So it has to be destroyed by the caller.
	 *
	 * @param this 			message_t object
	 * @param ike_sa_id		pointer to ike_sa_id pointer which will be set
	 * @return				
	 * 						- SUCCESS
	 * 						- FAILED if no ike_sa_id is set
	 */
	status_t (*get_ike_sa_id) (message_t *this,ike_sa_id_t **ike_sa_id);

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
	 * @brief Sets the original initiator flag.
	 *
	 * @param this 					message_t object
	 * @param original_initiator		TRUE if message is from original initiator
	 */
	void (*set_original_initiator) (message_t *this,bool original_initiator);

	/**
	 * @brief Gets original initiator flag.
	 *
	 * @param this 			message_t object
	 * @return				TRUE if message is from original initiator, FALSE otherwise
	 */
	bool (*get_original_initiator) (message_t *this);

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
	 * @param this 			message_t object
	 * @param payload 		payload to append
	 */	
	void (*add_payload) (message_t *this, payload_t *payload);

	/**
	 * @brief Parses header of message
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
	 *
	 * @param this 		message_t object
	 * @return
	 * 					- SUCCESS if header could be parsed
	 * 					- NOT_SUPPORTED if unsupported payload are contained in body
	 * 					- FAILED if message type is not suppported!
	 *					- PARSE_ERROR if corrupted/invalid data found
	 * 					- VERIFY_ERROR if verification of some payload failed
	 */
	status_t (*parse_body) (message_t *this, crypter_t *crypter, signer_t *signer);

	/**
	 * @brief Generates the UDP packet of specific message
	 *
	 * @param this 		message_t object
	 * @return
	 * 					- SUCCESS if packet could be generated
	 * 					- EXCHANGE_TYPE_NOT_SET if exchange type is currently not set
	 * ....
	 */	
	status_t (*generate) (message_t *this, crypter_t *crypter, signer_t *signer, packet_t **packet);
	
	/**
	 * Verifies the structure of the message_t object. 
	 * 
	 * The payloads are checked for the correct occurence count.
	 *
	 * @param this 		message_t object
	 */
	status_t (*verify) (message_t *this);
	
	/**
	 * Gets the source host informations. 
	 * 
	 * @warning Returned host_t object is not getting cloned.
	 *
	 * @param this 		message_t object
	 * @return			host_t object representing source host
	 */	
	host_t * (*get_source) (message_t *this);
	
	/**
	 * Sets the source host informations. 
	 * 
	 * @warning host_t object is not getting cloned and gets destroyed by
	 * 			message_t.destroy or next call of message_t.set_source.
	 *
	 * @param this 		message_t object
	 * @param host		host_t object representing source host
	 */	
	void (*set_source) (message_t *this, host_t *host);

	/**
	 * Gets the destination host informations. 
	 * 
	 * @warning Returned host_t object is not getting cloned.
	 *
	 * @param this 		message_t object
	 * @return			host_t object representing destination host
	 */	
	host_t * (*get_destination) (message_t *this);

	/**
	 * Sets the destination host informations. 
	 * 
	 * @warning host_t object is not getting cloned and gets destroyed by
	 * 			message_t.destroy or next call of message_t.set_destination.
	 *
	 * @param this 		message_t object
	 * @param host		host_t object representing destination host
	 */	
	void (*set_destination) (message_t *this, host_t *host);
	
	/**
	 * Returns an iterator on all stored payloads.
	 * 
	 * @warning Don't insert payloads over this iterator. 
	 * 			Use message_t.add_payload instead.
	 *
	 * @param this 		message_t object
	 * @return			iterator_t object which has to get destroyd by the caller
	 */	
	iterator_t * (*get_payload_iterator) (message_t *this);
	
	/**
	 * Returns a clone of the internal stored packet_t object.
	 *
	 * @param this 		message_t object
	 * @return			packet_t object as clone of internal one
	 */	
	packet_t * (*get_packet) (message_t *this);
	
	/**
	 * Returns a clone of the internal stored packet_t data.
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
 * Creates an message_t object from a incoming UDP Packet.
 * 
 * @warning the given packet_t object is not copied and gets 
 *			destroyed in message_t's destroy call.
 * 
 * @warning Packet is not parsed in here!
 * 
 * - exchange_type is set to NOT_SET
 * - original_initiator is set to TRUE
 * - is_request is set to TRUE
 * 
 * @param packet		packet_t object which is assigned to message					  
 * 
 * @return 				created message_t object
 * 
 * @ingroup encoding
 */
message_t * message_create_from_packet(packet_t *packet);


/**
 * Creates an empty message_t object.
 *
 * - exchange_type is set to NOT_SET
 * - original_initiator is set to TRUE
 * - is_request is set to TRUE
 * 
 * @return created message_t object
 *
 * @ingroup encoding
 */
message_t * message_create();

#endif /*MESSAGE_H_*/
