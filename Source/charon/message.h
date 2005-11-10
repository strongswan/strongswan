/**
 * @file message.h
 *
 * @brief Class message_t. Object of this type represents an IKEv2-Message.
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

#include "types.h"
#include "packet.h"
#include "ike_sa_id.h"


/**
 * Major version of IKEv2-Protocol. Always 2
 */
#define IKE_V2_MAJOR_VERSION 2

/**
 * Minor version of IKEv2-Protocol. Always 0
 */
#define IKE_V2_MINOR_VERSION 0

/**
 * Flag in IKEv2-Header. Always 0
 */
#define HIGHER_VERSION_SUPPORTED_FLAG 0
/**
 * @brief Different types of IKE-Exchanges.
 *
 * See RFC for different types.
 */
typedef enum exchange_type_e exchange_type_t;

enum exchange_type_e{

	/**
	 * NOT_SET, not a official message type :-)
	 */
	NOT_SET = 0,

	/**
	 * IKE_SA_INIT
	 */
	IKE_SA_INIT = 34,
	/**
	 * IKE_AUTH
	 */
	IKE_AUTH = 35,
	/**
	 * CREATE_CHILD_SA
	 */
	CREATE_CHILD_SA = 36,
	/**
	 * INFORMATIONAL
	 */
	INFORMATIONAL = 37 
};

/**
 * @brief This class is used to represent an IKEv2-Message.
 *
 * An IKEv2-Message is either a request or response.
 */
typedef struct message_s message_t;

struct message_s {

	/**
	 * @brief Sets the Message ID of the message.
	 *
	 * @param this 			message_t object
	 * @param message_id		message_id to set
	 * @return				SUCCESS
	 */
	status_t (*set_message_id) (message_t *this,u_int32_t message_id);

	/**
	 * @brief Gets the Message ID of the message.
	 *
	 * @param this 			message_t object
	 * @return				message_id type of the message
	 */
	u_int32_t (*get_message_id) (message_t *this);

	/**
	 * @brief Sets the IKE_SA ID of the message.
	 * 
	 * @warning ike_sa_id gets cloned  internaly and 
	 * so can be destroyed afterwards.
	 *
	 * @param this 			message_t object
	 * @param ike_sa_id		ike_sa_id to set
	 * @return				
	 * 						- SUCCESS
	 * 						- OUT_OF_RES	 
	 * @return				SUCCESS
	 */
	status_t (*set_ike_sa_id) (message_t *this,ike_sa_id_t * ike_sa_id);

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
	 * 						- OUT_OF_RES
	 * 						- FAILED if no ike_sa_id is set
	 */
	status_t (*get_ike_sa_id) (message_t *this,ike_sa_id_t **ike_sa_id);

	/**
	 * @brief Sets the exchange type of the message.
	 *
	 * @param this 			message_t object
	 * @param exchange_type	exchange_type to set
	 * @return				SUCCESS
	 */
	status_t (*set_exchange_type) (message_t *this,exchange_type_t exchange_type);

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
	 * @return						SUCCESS
	 */
	status_t (*set_original_initiator) (message_t *this,bool original_initiator);

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
	 * @return						SUCCESS
	 */
	status_t (*set_request) (message_t *this,bool request);

	/**
	 * @brief Gets request flag.
	 *
	 * @param this 			message_t object
	 * @return				TRUE if message is a request, FALSE if it is a reply
	 */
	bool (*get_request) (message_t *this);

	/**
	 * @brief Generates the UDP packet of specific message
	 *
	 * @param this 		message_t object
	 * @return
	 * 					- SUCCESS if packet could be generated
	 * 					- EXCHANGE_TYPE_NOT_SET if exchange type is currently not set
	 * ....
	 */
	status_t (*generate_packet) (message_t *this, packet_t **packet);
	
	/**
	 * @brief Destroys a message and all including objects
	 *
	 * @param this 		message_t object
	 * @return 			SUCCESS
	 */
	status_t (*destroy) (message_t *this);
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
 * @return 
 * 					- created message_t object
 * 					- NULL if out of ressources
 */
message_t * message_create_from_packet(packet_t *packet);


/**
 * Creates an empty message_t object.
 *
 * - exchange_type is set to NOT_SET
 * - original_initiator is set to TRUE
 * - is_request is set to TRUE
 * 
 * @return 
 * 					- created message_t object
 * 					- NULL if out of ressources
 */
message_t * message_create();

#endif /*MESSAGE_H_*/
