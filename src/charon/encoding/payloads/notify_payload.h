/**
 * @file notify_payload.h
 * 
 * @brief Interface of notify_payload_t.
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


#ifndef NOTIFY_PAYLOAD_H_
#define NOTIFY_PAYLOAD_H_

#include <types.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/proposal_substructure.h>
#include <utils/linked_list.h>

/**
 * Notify payload length in bytes without any spi and notification data.
 * 
 * @ingroup payloads
 */
#define NOTIFY_PAYLOAD_HEADER_LENGTH 8

typedef enum notify_type_t notify_type_t;


/** 
 * @brief Notify message types.
 * 
 * See IKEv2 RFC 3.10.1.
 * 
 * @ingroup payloads
 */
enum notify_type_t {
	/* notify error messages */
	UNSUPPORTED_CRITICAL_PAYLOAD = 1,
	INVALID_IKE_SPI = 4,
	INVALID_MAJOR_VERSION = 5,
	INVALID_SYNTAX = 7,
	INVALID_MESSAGE_ID = 9,
	INVALID_SPI = 11,
	NO_PROPOSAL_CHOSEN = 14,
	INVALID_KE_PAYLOAD = 17,
	AUTHENTICATION_FAILED = 24,
	SINGLE_PAIR_REQUIRED = 34,
	NO_ADDITIONAL_SAS = 35,
	INTERNAL_ADDRESS_FAILURE = 36,
	FAILED_CP_REQUIRED = 37,
	TS_UNACCEPTABLE = 38,
	INVALID_SELECTORS = 39,
	/* notify status messages */
	INITIAL_CONTACT = 16384,
	SET_WINDOW_SIZE = 16385,
	ADDITIONAL_TS_POSSIBLE = 16386,
	IPCOMP_SUPPORTED = 16387,
	NAT_DETECTION_SOURCE_IP = 16388,
	NAT_DETECTION_DESTINATION_IP = 16389,
	COOKIE = 16390,
	USE_TRANSPORT_MODE = 16391,
	HTTP_CERT_LOOKUP_SUPPORTED = 16392,
	REKEY_SA = 16393,
	ESP_TFC_PADDING_NOT_SUPPORTED = 16394,
	NON_FIRST_FRAGMENTS_ALSO = 16395,
	/* mobike extension, RFC4555 */
	MOBIKE_SUPPORTED = 16396,
	ADDITIONAL_IP4_ADDRESS = 16397,
	ADDITIONAL_IP6_ADDRESS = 16398,
	NO_ADDITIONAL_ADDRESSES = 16399,
	UPDATE_SA_ADDRESSES = 16400,
	COOKIE2 = 16401,
	NO_NATS_ALLOWED = 16402,
	/* repeated authentication extension, RFC4478 */
	AUTH_LIFETIME = 16403,
};

/** 
 * String mappings for notify_type_t.
 * 
 * @ingroup payloads
 */
extern mapping_t notify_type_m[];


typedef struct notify_payload_t notify_payload_t;

/**
 * @brief Class representing an IKEv2-Notify Payload.
 * 
 * The Notify Payload format is described in Draft section 3.10.
 * 
 * @b Constructors:
 * - notify_payload_create()
 * - notify_payload_create_from_protocol_and_type()
 * 
 * @todo Build specified constructor/getter for notify's
 *
 * @ingroup payloads
 */
struct notify_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Gets the protocol id of this payload.
	 * 	
	 * @param this 		calling notify_payload_t object
	 * @return 			protocol id of this payload
	 */
	u_int8_t (*get_protocol_id) (notify_payload_t *this);

	/**
	 * @brief Sets the protocol id of this payload.
	 * 	
	 * @param this 			calling notify_payload_t object
	 * @param protocol_id	protocol id to set
	 */
	void (*set_protocol_id) (notify_payload_t *this, u_int8_t protocol_id);

	/**
	 * @brief Gets the notify message type of this payload.
	 * 	
	 * @param this 		calling notify_payload_t object
	 * @return 			notify message type of this payload
	 */
	notify_type_t (*get_notify_type) (notify_payload_t *this);

	/**
	 * @brief Sets notify message type of this payload.
	 * 	
	 * @param this 		calling notify_payload_t object
	 * @param type		notify message type to set
	 */
	void (*set_notify_type) (notify_payload_t *this, notify_type_t type);

	/**
	 * @brief Returns the currently set spi of this payload.
	 * 
	 * This is only valid for notifys with protocol AH|ESP
	 *
	 * @param this 	calling notify_payload_t object
	 * @return 		SPI value
	 */
	u_int32_t (*get_spi) (notify_payload_t *this);
	
	/**
	 * @brief Sets the spi of this payload.
	 * 
	 * This is only valid for notifys with protocol AH|ESP
	 * 
	 * @param this 	calling notify_payload_t object
	 * @param spi	SPI value
	 */
	void (*set_spi) (notify_payload_t *this, u_int32_t spi);

	/**
	 * @brief Returns the currently set notification data of payload.
	 * 	
	 * @warning Returned data are not copied.
	 * 
	 * @param this 	calling notify_payload_t object
	 * @return 		chunk_t pointing to the value
	 */
	chunk_t (*get_notification_data) (notify_payload_t *this);
	
	/**
	 * @brief Sets the notification data of this payload.
	 * 	
	 * @warning Value is getting copied.
	 * 
	 * @param this 					calling notify_payload_t object
	 * @param notification_data 	chunk_t pointing to the value to set
	 */
	void (*set_notification_data) (notify_payload_t *this, chunk_t notification_data);

	/**
	 * @brief Destroys an notify_payload_t object.
	 *
	 * @param this 	notify_payload_t object to destroy
	 */
	void (*destroy) (notify_payload_t *this);
};

/**
 * @brief Creates an empty notify_payload_t object
 * 
 * @return			created notify_payload_t object
 * 
 * @ingroup payloads
 */
notify_payload_t *notify_payload_create(void);

/**
 * @brief Creates an notify_payload_t object of specific type for specific protocol id.
 * 
 * @param protocol_id			protocol id (IKE, AH or ESP)
 * @param type					notify type (see notify_type_t)
 * @return						notify_payload_t object
 * 
 * @ingroup payloads
 */
notify_payload_t *notify_payload_create_from_protocol_and_type(protocol_id_t protocol_id, notify_type_t type);


#endif /*NOTIFY_PAYLOAD_H_*/
