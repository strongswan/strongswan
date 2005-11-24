/**
 * @file notify_payload.h
 * 
 * @brief Declaration of the class notify_payload_t. 
 * 
 * An object of this type represents an IKEv2 Notify-Payload.
 * 
 * See section 3.10 of Draft for details of this payload type.
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


#ifndef NOTIFY_PAYLOAD_H_
#define NOTIFY_PAYLOAD_H_

#include <types.h>
#include <encoding/payloads/payload.h>
#include <utils/linked_list.h>

/**
 * Critical flag must not be set
 */
#define NOTIFY_PAYLOAD_CRITICAL_FLAG FALSE;

/**
 * Notify payload length in bytes without any spi and notification data
 */
#define NOTIFY_PAYLOAD_HEADER_LENGTH 8

typedef struct notify_payload_t notify_payload_t;

/**
 * Object representing an IKEv2-Notify Payload
 * 
 * The Notify Payload format is described in Draft section 3.10.
 * 
 */
struct notify_payload_t {
	/**
	 * implements payload_t interface
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
	 * @param this 				calling notify_payload_t object
	 * @param protocol_id		protocol id to set
	 * @return 					SUCCESS
	 */
	status_t (*set_protocol_id) (notify_payload_t *this, u_int8_t protocol_id);

	/**
	 * @brief Gets the notify message type of this payload.
	 * 	
	 * @param this 				calling notify_payload_t object
	 * @return 					 notify message type of this payload
	 */
	u_int16_t (*get_notify_message_type) (notify_payload_t *this);

	/**
	 * @brief Sets notify message type of this payload.
	 * 	
	 * @param this 					calling notify_payload_t object
	 * @param notify_message_type	notify message type to set
	 * @return 						SUCCESS
	 */
	status_t (*set_notify_message_type) (notify_payload_t *this, u_int16_t notify_message_type);

	/**
	 * @brief Returns the currently set spi of this payload.
	 * 	
	 * @warning Returned data are not copied.
	 * 
	 * @param this 	calling notify_payload_t object
	 * @return 		chunk_t pointing to the value
	 */
	chunk_t (*get_spi) (notify_payload_t *this);
	
	/**
	 * @brief Sets the spi of this payload.
	 * 	
	 * @warning Value is getting copied.
	 * 
	 * @param this 				calling notify_payload_t object
	 * @param spi				chunk_t pointing to the value to set
	 * @return 		
	 * 							- SUCCESS or
	 * 							- OUT_OF_RES
	 */
	status_t (*set_spi) (notify_payload_t *this, chunk_t spi);

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
	 * @param this 				calling notify_payload_t object
	 * @param notification_data 	chunk_t pointing to the value to set
	 * @return 		
	 * 							- SUCCESS or
	 * 							- OUT_OF_RES
	 */
	status_t (*set_notification_data) (notify_payload_t *this, chunk_t notification_data);

	/**
	 * @brief Destroys an notify_payload_t object.
	 *
	 * @param this 	notify_payload_t object to destroy
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*destroy) (notify_payload_t *this);
};

/**
 * @brief Creates an empty notify_payload_t object
 * 
 * @return			
 * 					- created notify_payload_t object, or
 * 					- NULL if failed
 */
notify_payload_t *notify_payload_create();


#endif /*NOTIFY_PAYLOAD_H_*/
