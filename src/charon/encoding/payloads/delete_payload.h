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
 *
 * $Id$
 */

/**
 * @defgroup delete_payload delete_payload
 * @{ @ingroup payloads
 */

#ifndef DELETE_PAYLOAD_H_
#define DELETE_PAYLOAD_H_

typedef struct delete_payload_t delete_payload_t;

#include <library.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/proposal_substructure.h>

/**
 * Length of a delete payload without the SPI in bytes.
 */
#define DELETE_PAYLOAD_HEADER_LENGTH 8

/**
 * Class representing an IKEv2 DELETE payload.
 *
 * The DELETE payload format is described in RFC section 3.11.
 */
struct delete_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;
	
	/**
	 * Get the protocol ID.
	 *
	 * @return				protocol ID
	 */
	protocol_id_t (*get_protocol_id) (delete_payload_t *this);
	
	/**
	 * Add an SPI to the list of deleted SAs.
	 *
	 * @param spi			spi to add
	 */
	void (*add_spi) (delete_payload_t *this, u_int32_t spi);
	
	/**
	 * Get an iterator over the SPIs.
	 *
	 * The iterate() function returns a pointer to a u_int32_t SPI.
	 *
	 * @return				iterator over SPIs
	 */
	iterator_t *(*create_spi_iterator) (delete_payload_t *this);
	
	/**
	 * Destroys an delete_payload_t object.
	 */
	void (*destroy) (delete_payload_t *this);
};

/**
 * Creates an empty delete_payload_t object.
 * 
 * @param protocol_id	protocol, such as AH|ESP
 * @return 				delete_payload_t object
 */
delete_payload_t *delete_payload_create(protocol_id_t protocol_id);

#endif /** DELETE_PAYLOAD_H_ @}*/
