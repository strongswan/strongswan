/**
 * @file ke_payload.h
 * 
 * @brief Declaration of the class ke_payload_t. 
 * 
 * An object of this type represents an IKEv2 KE-Payload.
 * 
 * See section 3.4 of RFC for details of this payload type.
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

#ifndef KE_PAYLOAD_H_
#define KE_PAYLOAD_H_

#include "../types.h"
#include "payload.h"
#include "../utils/linked_list.h"

/**
 * Critical flag must not be set
 */
#define KE_PAYLOAD_CRITICAL_FLAG FALSE;

/**
 * KE payload length in bytes without any key exchange data
 */
#define KE_PAYLOAD_HEADER_LENGTH 8

/**
 * Object representing an IKEv2-KE Payload
 * 
 * The KE Payload format is described in RFC section 3.4.
 * 
 */
typedef struct ke_payload_s ke_payload_t;

struct ke_payload_s {
	/**
	 * implements payload_t interface
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Returns the currently set key exchange data of this KE payload.
	 * 	
	 * @warning Returned data are not copied.
	 * 
	 * @param this 	calling ke_payload_t object
	 * @return 		chunk_t pointing to the value
	 */
	chunk_t (*get_key_exchange_data) (ke_payload_t *this);
	
	/**
	 * @brief Sets the key exchange data of this KE payload.
	 * 	
	 * @warning Value is getting copied.
	 * 
	 * @param this 				calling ke_payload_t object
	 * @param key_exchange_data 	chunk_t pointing to the value to set
	 * @return 		
	 * 							- SUCCESS or
	 * 							- OUT_OF_RES
	 */
	status_t (*set_key_exchange_data) (ke_payload_t *this, chunk_t key_exchange_data);

	/**
	 * @brief Gets the Diffie-Hellman Group Number of this KE payload.
	 * 	
	 * @param this 		calling ke_payload_t object
	 * @return 			DH Group Number of this payload
	 */
	u_int16_t (*get_dh_group_number) (ke_payload_t *this);

	/**
	 * @brief Sets the Diffie-Hellman Group Number of this KE payload.
	 * 	
	 * @param this 				calling ke_payload_t object
	 * @param dh_group_number	DH Group to set
	 * @return 					SUCCESS
	 */
	status_t (*set_dh_group_number) (ke_payload_t *this, u_int16_t dh_group_number);

	/**
	 * @brief Destroys an ke_payload_t object.
	 *
	 * @param this 	ke_payload_t object to destroy
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*destroy) (ke_payload_t *this);
};

/**
 * @brief Creates an empty ke_payload_t object
 * 
 * @return			
 * 					- created ke_payload_t object, or
 * 					- NULL if failed
 */
 
ke_payload_t *ke_payload_create();


#endif /*KE_PAYLOAD_H_*/
