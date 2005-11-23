/**
 * @file ike_header.h
 * 
 * @brief Declaration of the class ike_header_t. 
 * 
 * An object of this type represents an ike header and is used to 
 * generate and parse ike headers.
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

#ifndef IKE_HEADER_H_
#define IKE_HEADER_H_

#include <types.h>
#include <payloads/payload.h>

/**
 * Major Version of IKEv2
 */
#define IKE_MAJOR_VERSION 2

/**
 * Minor Version of IKEv2
 */
#define IKE_MINOR_VERSION 0

/**
 * Flag in IKEv2-Header. Always 0
 */
#define HIGHER_VERSION_SUPPORTED_FLAG 0

/**
 * Length of IKE Header in Bytes
 */
#define IKE_HEADER_LENGTH 28

/**
 * @brief Different types of IKE-Exchanges.
 *
 * See RFC for different types.
 */
typedef enum exchange_type_e exchange_type_t;

enum exchange_type_e{

	/**
	 * EXCHANGE_TYPE_UNDEFINED, not a official message type :-)
	 */
	EXCHANGE_TYPE_UNDEFINED = 240,
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

extern mapping_t exchange_type_m[];

/**
 * Object representing an IKEv2-Header
 * 
 * The header format of an IKEv2-Message is compatible to the 
 * ISAKMP-Header format to allow implementations supporting 
 * both versions of the IKE-protocol.
 * 
 */
typedef struct ike_header_s ike_header_t;

struct ike_header_s {
	/**
	 * implements payload_t interface
	 */
	payload_t payload_interface;
	
	/**
	 * @brief get the initiator spi
	 *
	 * @param this 			ike_header_t object
	 * @return 				initiator_spi
	 */
	u_int64_t (*get_initiator_spi) (ike_header_t *this);
	
	/**
	 * @brief set the initiator spi
	 *
	 * @param this 			ike_header_t object
	 * @param initiator_spi	initiator_spi
	 */
	void (*set_initiator_spi) (ike_header_t *this, u_int64_t initiator_spi);
	
	/**
	 * @brief get the responder spi
	 *
	 * @param this 			ike_header_t object
	 * @return 				responder_spi
	 */
	u_int64_t (*get_responder_spi) (ike_header_t *this);
	
	/**
	 * @brief set the responder spi
	 *
	 * @param this 			ike_header_t object
	 * @param responder_spi	responder_spi
	 */
	void (*set_responder_spi) (ike_header_t *this, u_int64_t responder_spi);
	
	/**
	 * @brief get the major version
	 *
	 * @param this 			ike_header_t object
	 * @return 				major version
	 */
	u_int8_t (*get_maj_version) (ike_header_t *this);
	
	/**
	 * @brief get the mainor version
	 *
	 * @param this 			ike_header_t object
	 * @return 				minor version
	 */
	u_int8_t (*get_min_version) (ike_header_t *this);
	
	/**
	 * @brief get the response flag
	 *
	 * @param this 			ike_header_t object
	 * @return 				response flag
	 */
	bool (*get_response_flag) (ike_header_t *this);
	
	/**
	 * @brief Set the response flag
	 *
	 * @param this 			ike_header_t object
	 * @param response		response flag
	 * 
	 */
	void (*set_response_flag) (ike_header_t *this, bool response);
	/**
	 * @brief get "higher version supported"-flag
	 *
	 * @param this 			ike_header_t object
	 * @return 				version flag
	 */
	bool (*get_version_flag) (ike_header_t *this);
	
	/**
	 * @brief get the initiator flag
	 *
	 * @param this 			ike_header_t object
	 * @return 				initiator flag
	 */
	bool (*get_initiator_flag) (ike_header_t *this);
	
	/**
	 * @brief Set the initiator flag
	 *
	 * @param this 			ike_header_t object
	 * @param initiator		initiator flag
	 * 
	 */
	void (*set_initiator_flag) (ike_header_t *this, bool initiator);

	/**
	 * @brief get the exchange type
	 *
	 * @param this 			ike_header_t object
	 * @return 				 exchange type
	 */
	u_int8_t (*get_exchange_type) (ike_header_t *this);
	
	/**
	 * @brief set the  exchange type
	 *
	 * @param this 			ike_header_t object
	 * @param exchange_type	exchange type
	 */
	void (*set_exchange_type) (ike_header_t *this, u_int8_t exchange_type);
	
	/**
	 * @brief get the message id
	 *
	 * @param this 			ike_header_t object
	 * @return 				message id
	 */
	u_int32_t (*get_message_id) (ike_header_t *this);
	
	/**
	 * @brief set the message id
	 *
	 * @param this 			ike_header_t object
	 * @param initiator_spi	message id
	 */
	void (*set_message_id) (ike_header_t *this, u_int32_t message_id);
	
	/**
	 * @brief Destroys a ike_header_t object.
	 *
	 * @param this 	ike_header_t object to destroy
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*destroy) (ike_header_t *this);
};

/**
 * @brief Create an ike_header_t object
 * 
 * @return			
 * 					- created ike_header, or
 * 					- NULL if failed
 */
 
ike_header_t *ike_header_create();

#endif /*IKE_HEADER_H_*/
