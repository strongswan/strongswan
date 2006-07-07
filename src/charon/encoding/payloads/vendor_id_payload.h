/**
 * @file vendor_id_payload.h
 * 
 * @brief Interface of vendor_id_payload_t.
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

#ifndef VENDOR_ID_PAYLOAD_H_
#define VENDOR_ID_PAYLOAD_H_

#include <types.h>
#include <encoding/payloads/payload.h>

/**
 * Length of a VENDOR ID payload without the VID data in bytes.
 * 
 * @ingroup payloads
 */
#define VENDOR_ID_PAYLOAD_HEADER_LENGTH 4


typedef struct vendor_id_payload_t vendor_id_payload_t;

/**
 * @brief Class representing an IKEv2 VENDOR ID payload.
 * 
 * The VENDOR ID payload format is described in RFC section 3.12.
 * 
 * @b Constructors:
 * - vendor_id_payload_create()
 * 
 * @ingroup payloads
 */
struct vendor_id_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * @brief Set the VID data.
	 * 
	 * Data are getting cloned.
	 *
	 * @param this 			calling vendor_id_payload_t object
	 * @param data			VID data as chunk_t
	 */
	void (*set_data) (vendor_id_payload_t *this, chunk_t data);
	
	/**
	 * @brief Get the VID data.
	 * 
	 * Returned data are a copy of the internal one.
	 *
	 * @param this 			calling vendor_id_payload_t object
	 * @return				VID data as chunk_t
	 */
	chunk_t (*get_data_clone) (vendor_id_payload_t *this);
	
	/**
	 * @brief Get the VID data.
	 * 
	 * Returned data are NOT copied.
	 *
	 * @param this 			calling vendor_id_payload_t object
	 * @return				VID data as chunk_t
	 */
	chunk_t (*get_data) (vendor_id_payload_t *this);
	
	/**
	 * @brief Destroys an vendor_id_payload_t object.
	 *
	 * @param this 	vendor_id_payload_t object to destroy
	 */
	void (*destroy) (vendor_id_payload_t *this);
};

/**
 * @brief Creates an empty vendor_id_payload_t object.
 * 
 * @return vendor_id_payload_t object
 * 
 * @ingroup payloads
 */
vendor_id_payload_t *vendor_id_payload_create(void);


#endif /* VENDOR_ID_PAYLOAD_H_ */
