/**
 * @file id_payload.h
 * 
 * @brief Interface of id_payload_t.
 * 
 */

/*
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


#ifndef ID_PAYLOAD_H_
#define ID_PAYLOAD_H_

#include <types.h>
#include <utils/identification.h>
#include <encoding/payloads/payload.h>

/**
 * Length of a id payload without the data in bytes.
 * 
 * @ingroup payloads
 */
#define ID_PAYLOAD_HEADER_LENGTH 8


typedef struct id_payload_t id_payload_t;

/**
 * Object representing an IKEv2 ID payload.
 * 
 * The ID payload format is described in RFC section 3.5.
 * 
 * @b Constructors:
 * - id_payload_create_from_identification()
 * - id_payload_create()
 * 
 * @ingroup payloads
 */
struct id_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * @brief Set the ID type.
	 *
	 * @param this 			calling id_payload_t object
	 * @param type			Type of ID
	 */
	void (*set_id_type) (id_payload_t *this, id_type_t type);
	
	/**
	 * @brief Get the ID type.
	 *
	 * @param this 			calling id_payload_t object
	 * @return				type of the ID 
	 */
	id_type_t (*get_id_type) (id_payload_t *this);
	
	/**
	 * @brief Set the ID data.
	 * 
	 * Data are getting cloned.
	 *
	 * @param this 			calling id_payload_t object
	 * @param data			ID data as chunk_t
	 */
	void (*set_data) (id_payload_t *this, chunk_t data);
	
	/**
	 * @brief Get the ID data.
	 * 
	 * Returned data are a copy of the internal one
	 *
	 * @param this 			calling id_payload_t object
	 * @return				ID data as chunk_t
	 */
	chunk_t (*get_data_clone) (id_payload_t *this);
	
	/**
	 * @brief Get the ID data.
	 * 
	 * Returned data are NOT copied.
	 *
	 * @param this 			calling id_payload_t object
	 * @return				ID data as chunk_t
	 */
	chunk_t (*get_data) (id_payload_t *this);

	/**
	 * @brief Creates an identification object of this id payload.
	 * 
	 * Returned object has to get destroyed by the caller.
	 *
	 * @param this 			calling id_payload_t object
	 * @return				identification_t object 
	 */
	identification_t *(*get_identification) (id_payload_t *this);
	
	/**
	 * @brief Get the type of ID payload (IDi or IDr).
	 *
	 * @param this 			calling id_payload_t object
	 * @return
	 * 						- TRUE if this payload is of type IDi
	 * 						- FALSE if this payload is of type IDr
	 * 
	 */
	bool (*get_initiator) (id_payload_t *this);
	
	/**
	 * @brief Set the type of ID payload (IDi or IDr).
	 *
	 * @param this 			calling id_payload_t object
	 * @param is_initiator	
	 * 						- TRUE if this payload is of type IDi
	 * 						- FALSE if this payload is of type IDr
	 * 
	 */
	void (*set_initiator) (id_payload_t *this,bool is_initiator);
	
	/**
	 * @brief Destroys an id_payload_t object.
	 *
	 * @param this 	id_payload_t object to destroy
	 */
	void (*destroy) (id_payload_t *this);
};

/**
 * @brief Creates an empty id_payload_t object.
 * 
 * @param is_initiator	
 * 						- TRUE if this payload is of type IDi
 * 						- FALSE if this payload is of type IDr
 * 
 * @return				id_payload_t object
 * 
 * @ingroup payloads
 */
id_payload_t *id_payload_create(bool is_initiator);

/**
 * @brief Creates an id_payload_t from an existing identification_t object.
 * 
 * @param is_initiator	
 * 							- TRUE if this payload is of type IDi
 * 							- FALSE if this payload is of type IDr
 * @param identification	identification_t object
 * @return					id_payload_t object
 * 
 * @ingroup payloads
 */
id_payload_t *id_payload_create_from_identification(bool is_initiator,identification_t *identification);



#endif /* ID_PAYLOAD_H_ */
