/**
 * @file delete_payload.h
 * 
 * @brief Interface of delete_payload_t.
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

#ifndef DELETE_PAYLOAD_H_
#define DELETE_PAYLOAD_H_

typedef struct delete_payload_t delete_payload_t;

#include <library.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/proposal_substructure.h>

/**
 * Length of a delete payload without the SPI in bytes.
 *
 * @ingroup payloads
 */
#define DELETE_PAYLOAD_HEADER_LENGTH 8

/**
 * @brief Class representing an IKEv2 DELETE payload.
 *
 * The DELETE payload format is described in RFC section 3.11.
 *
 * @b Constructors:
 * - delete_payload_create()
 *
 * @todo Implement better setter/getters
 *
 * @ingroup payloads
 */
struct delete_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Get the protocol ID.
	 *
	 * @param this 			calling delete_payload_t object
	 * @return				protocol ID
	 */
	protocol_id_t (*get_protocol_id) (delete_payload_t *this);
	
	/**
	 * @brief Add an SPI to the list of deleted SAs.
	 *
	 * @param this 			calling delete_payload_t object
	 * @param spi			spi to add
	 */
	void (*add_spi) (delete_payload_t *this, u_int32_t spi);
	
	/**
	 * @brief Get an iterator over the SPIs.
	 *
	 * The iterate() function returns a pointer to a u_int32_t SPI.
	 *
	 * @param this 			calling delete_payload_t object
	 * @return				iterator over SPIs
	 */
	iterator_t *(*create_spi_iterator) (delete_payload_t *this);
	
	/**
	 * @brief Destroys an delete_payload_t object.
	 *
	 * @param this 	delete_payload_t object to destroy
	 */
	void (*destroy) (delete_payload_t *this);
};

/**
 * @brief Creates an empty delete_payload_t object.
 * 
 * @param protocol_id	protocol, such as AH|ESP
 * @return 				delete_payload_t object
 * 
 * @ingroup payloads
 */
delete_payload_t *delete_payload_create(protocol_id_t protocol_id);

#endif /* DELETE_PAYLOAD_H_ */
