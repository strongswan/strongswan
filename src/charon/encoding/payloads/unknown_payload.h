/**
 * @file unknown_payload.h
 * 
 * @brief Interface of unknown_payload_t.
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

#ifndef UNKNOWN_PAYLOAD_H_
#define UNKNOWN_PAYLOAD_H_

#include <types.h>
#include <encoding/payloads/payload.h>

/**
 * Header length of the unknown payload.
 * 
 * @ingroup payloads
 */
#define UNKNOWN_PAYLOAD_HEADER_LENGTH 4


typedef struct unknown_payload_t unknown_payload_t;

/**
 * @brief Payload which can't be processed further.
 * 
 * When the parser finds an unknown payload, he builds an instance of
 * this class. This allows further processing of this payload, such as
 * a check for the critical bit in the header.
 * 
 * @b Constructors:
 * - unknown_payload_create()
 * 
 * @ingroup payloads
 */
struct unknown_payload_t {
	
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Get the raw data of this payload, without 
	 * the generic payload header.
	 * 
	 * Returned data are NOT copied and must not be freed.
	 *
	 * @param this 			calling unknown_payload_t object
	 * @return				data as chunk_t
	 */
	chunk_t (*get_data) (unknown_payload_t *this);
	
	/**
	 * @brief Get the critical flag.
	 *
	 * @param this			calling unknown_payload_t object
	 * @return				TRUE if payload is critical, FALSE if not
	 */
	bool (*is_critical) (unknown_payload_t *this);
	
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
 * @return unknown_payload_t object
 * 
 * @ingroup payloads
 */
unknown_payload_t *unknown_payload_create(void);


#endif /* UNKNOWN_PAYLOAD_H_ */
