/**
 * @file unknown_payload.h
 * 
 * @brief Interface of unknown_payload_t.
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

#ifndef _UNKNOWN_PAYLOAD_H_
#define _UNKNOWN_PAYLOAD_H_

#include <types.h>
#include <encoding/payloads/payload.h>

/**
 * Length of a default payload header.
 * 
 * @ingroup payloads
 */
#define DEFAULT_PAYLOAD_HEADER_LENGTH 4


typedef struct unknown_payload_t unknown_payload_t;

/**
 * Object representing an unknown IKEv2 payload.
 * 
 * @ingroup payloads
 * 
 */
struct unknown_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Set the Data of the unknown payload.
	 * 
	 * Data are getting cloned.
	 *
	 * @param this 			calling unknown_payload_t object
	 * @param data			data following the header as chunk_t
	 */
	void (*set_data) (unknown_payload_t *this, chunk_t data);
	
	/**
	 * @brief Get the data of the message.
	 * 
	 * Returned data are a copy of the internal one.
	 *
	 * @param this 			calling unknown_payload_t object
	 * @return				data as chunk_t
	 */
	chunk_t (*get_data_clone) (unknown_payload_t *this);
	
	/**
	 * @brief Get the data of the message.
	 * 
	 * Returned data are NOT copied.
	 *
	 * @param this 			calling unknown_payload_t object
	 * @return				data as chunk_t
	 */
	chunk_t (*get_data) (unknown_payload_t *this);

	/**
	 * @brief Set the real Type of this payload.
	 *
	 * @param this 			calling unknown_payload_t object
	 * @param type			real type of this payload.
	 */
	
	void (*set_real_type) (unknown_payload_t *this,payload_type_t type);
	
	/**
	 * @brief Get the real Type of this payload.
	 *
	 * @param this 			calling unknown_payload_t object
	 * @return				real type of this payload.
	 */
	payload_type_t (*get_real_type) (unknown_payload_t *this);
	
	/**
	 * @brief Destroys an unknown_payload_t object.
	 *
	 * @param this 	unknown_payload_t object to destroy
	 */
	void (*destroy) (unknown_payload_t *this);
};

/**
 * @brief Creates an empty unknown_payload_t object.
 * 
 * @return				created unknown_payload_t object
 * 
 * @ingroup payloads
 */
unknown_payload_t *unknown_payload_create();


#endif //_UNKNOWN_PAYLOAD_H_
