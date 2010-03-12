/*
 * Copyright (C) 2005-2009 Martin Willi
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

/**
 * @defgroup vendor_id_payload vendor_id_payload
 * @{ @ingroup payloads
 */

#ifndef VENDOR_ID_PAYLOAD_H_
#define VENDOR_ID_PAYLOAD_H_

typedef struct vendor_id_payload_t vendor_id_payload_t;

#include <library.h>
#include <encoding/payloads/payload.h>

/**
 * Length of a VENDOR ID payload without the VID data in bytes.
 */
#define VENDOR_ID_PAYLOAD_HEADER_LENGTH 4

/**
 * Class representing an IKEv2 VENDOR ID payload.
 *
 * The VENDOR ID payload format is described in RFC section 3.12.
 */
struct vendor_id_payload_t {

	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Get the VID data.
	 *
	 * @return		VID data, pointing to an internal chunk_t
	 */
	chunk_t (*get_data)(vendor_id_payload_t *this);
};

/**
 * Creates an empty Vendor ID payload.
 *
 * @return			vendor ID payload
 */
vendor_id_payload_t *vendor_id_payload_create();

/**
 * Creates a vendor ID payload using a chunk of data
 *
 * @param data		data to use in vendor ID payload, gets owned by payload
 * @return			vendor ID payload
 */
vendor_id_payload_t *vendor_id_payload_create_data(chunk_t data);

#endif /** VENDOR_ID_PAYLOAD_H_ @}*/
