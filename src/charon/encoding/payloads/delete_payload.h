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

#include <types.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/proposal_substructure.h>

/**
 * Length of a delete payload without the SPI in bytes.
 * 
 * @ingroup payloads
 */
#define DELETE_PAYLOAD_HEADER_LENGTH 8



typedef struct delete_payload_t delete_payload_t;

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
	 * @brief Set the protocol ID.
	 *
	 * @param this 			calling delete_payload_t object
	 * @param protocol_id	protocol ID
	 * 
	 * @deprecated is set by constructor
	 */
	void (*set_protocol_id) (delete_payload_t *this, protocol_id_t protocol_id);
	
	/**
	 * @brief Get the protocol ID.
	 *
	 * @param this 			calling delete_payload_t object
	 * @return				protocol ID
	 */
	protocol_id_t (*get_protocol_id) (delete_payload_t *this);
	
	/**
	 * @brief Set the SPI size.
	 *
	 * @param this 			calling delete_payload_t object
	 * @param spi_size		SPI size
	 * 
	 * @deprecated is set by constructor
	 */
	void (*set_spi_size) (delete_payload_t *this, u_int8_t spi_size);
	
	/**
	 * @brief Get the SPI size.
	 *
	 * @param this 			calling delete_payload_t object
	 * @return				SPI size
	 */
	u_int8_t (*get_spi_size) (delete_payload_t *this);
	
	/**
	 * @brief Set the SPI count.
	 *
	 * @param this 			calling delete_payload_t object
	 * @param spi_count		SPI count
	 * 
	 * @deprecated is incremented via add_spi
	 */
	void (*set_spi_count) (delete_payload_t *this, u_int16_t spi_count);
	
	/**
	 * @brief Get the SPI count.
	 *
	 * @param this 			calling delete_payload_t object
	 * @return				Number of SPI's
	 */
	u_int16_t (*get_spi_count) (delete_payload_t *this);
	
	/**
	 * @brief Set the SPI's.
	 * 
	 * Data are getting cloned.
	 *
	 * @param this 			calling delete_payload_t object
	 * @param data			SPI's as chunk_t
	 *
	 * @deprecated use add_spi
	 */
	void (*set_spis) (delete_payload_t *this, chunk_t spis);
	
	/**
	 * @brief Get the SPI's.
	 * 
	 * Returned data are NOT copied.
	 *
	 * @param this 			calling delete_payload_t object
	 * @return				SPI's as chunk_t
	 * 
	 * @deprecated use create_spi_iterator
	 */
	chunk_t (*get_spis) (delete_payload_t *this);
	
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
	 * The resulting interators current() function returns
	 * u_int32_t SPIs directly.
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
