/*
 * Copyright (C) 2007 Tobias Brunner
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
 *
 * $Id$
 */

/**
 * @defgroup id_payload id_payload
 * @{ @ingroup payloads
 */

#ifndef ID_PAYLOAD_H_
#define ID_PAYLOAD_H_

typedef struct id_payload_t id_payload_t;

#include <library.h>
#include <utils/identification.h>
#include <encoding/payloads/payload.h>

/**
 * Length of a id payload without the data in bytes.
 */
#define ID_PAYLOAD_HEADER_LENGTH 8

/**
 * Object representing an IKEv2 ID payload.
 *
 * The ID payload format is described in RFC section 3.5.
 */
struct id_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Set the ID type.
	 *
	 * @param type			Type of ID
	 */
	void (*set_id_type) (id_payload_t *this, id_type_t type);
	
	/**
	 * Get the ID type.
	 *
	 * @return				type of the ID 
	 */
	id_type_t (*get_id_type) (id_payload_t *this);
	
	/**
	 * Set the ID data.
	 * 
	 * Data are getting cloned.
	 *
	 * @param data			ID data as chunk_t
	 */
	void (*set_data) (id_payload_t *this, chunk_t data);
	
	/**
	 * Get the ID data.
	 * 
	 * Returned data are a copy of the internal one
	 *
	 * @return				ID data as chunk_t
	 */
	chunk_t (*get_data_clone) (id_payload_t *this);
	
	/**
	 * Get the ID data.
	 * 
	 * Returned data are NOT copied.
	 *
	 * @return				ID data as chunk_t
	 */
	chunk_t (*get_data) (id_payload_t *this);

	/**
	 * Creates an identification object of this id payload.
	 * 
	 * Returned object has to get destroyed by the caller.
	 *
	 * @return				identification_t object 
	 */
	identification_t *(*get_identification) (id_payload_t *this);
	
	/**
	 * Destroys an id_payload_t object.
	 */
	void (*destroy) (id_payload_t *this);
};

/**
 * Creates an empty id_payload_t object.
 * 
 * @param payload_type	one of ID_INITIATOR, ID_RESPONDER
 * @return				id_payload_t object
 */
id_payload_t *id_payload_create(payload_type_t payload_type);

/**
 * Creates an id_payload_t from an existing identification_t object.
 * 
 * @param payload_type		one of ID_INITIATOR, ID_RESPONDER
 * @param identification	identification_t object
 * @return					id_payload_t object
 */
id_payload_t *id_payload_create_from_identification(payload_type_t payload_type,
											identification_t *identification);

#endif /* ID_PAYLOAD_H_ @} */
