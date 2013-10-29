/*
 * Copyright (C) 2005-2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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
 * @defgroup encryption_payload encryption_payload
 * @{ @ingroup payloads
 */

#ifndef ENCRYPTION_PAYLOAD_H_
#define ENCRYPTION_PAYLOAD_H_

typedef struct encryption_payload_t encryption_payload_t;

#include <library.h>
#include <crypto/aead.h>
#include <encoding/payloads/payload.h>

/**
 * The encryption payload as described in RFC section 3.14.
 */
struct encryption_payload_t {

	/**
	 * Implements payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Get the payload length.
	 *
	 * @return			(expected) payload length
	 */
	size_t (*get_length)(encryption_payload_t *this);

	/**
	 * Adds a payload to this encryption payload.
	 *
	 * @param payload		payload_t object to add
	 */
	void (*add_payload) (encryption_payload_t *this, payload_t *payload);

	/**
	 * Remove the first payload in the list
	 *
	 * @param payload		removed payload
	 * @return				payload, NULL if none left
	 */
	payload_t* (*remove_payload)(encryption_payload_t *this);

	/**
	 * Set the AEAD transform to use.
	 *
	 * @param aead		aead transform to use
	 */
	void (*set_transform) (encryption_payload_t *this, aead_t *aead);

	/**
	 * Generate, encrypt and sign contained payloads.
	 *
	 * @param mid			message ID
	 * @param assoc			associated data
	 * @return
	 * 						- SUCCESS if encryption successful
	 * 						- FAILED if encryption failed
	 * 						- INVALID_STATE if aead not supplied, but needed
	 */
	status_t (*encrypt) (encryption_payload_t *this, u_int64_t mid,
						 chunk_t assoc);

	/**
	 * Decrypt, verify and parse contained payloads.
	 *
	 * @param assoc			associated data
	 * @return
	 * 						- SUCCESS if parsing successful
	 *						- PARSE_ERROR if sub-payload parsing failed
	 * 						- VERIFY_ERROR if sub-payload verification failed
	 * 						- FAILED if integrity check failed
	 * 						- INVALID_STATE if aead not supplied, but needed
	 */
	status_t (*decrypt) (encryption_payload_t *this, chunk_t assoc);

	/**
	 * Destroys an encryption_payload_t object.
	 */
	void (*destroy) (encryption_payload_t *this);
};

/**
 * Creates an empty encryption_payload_t object.
 *
 * @param type		PLV2_ENCRYPTED or PLV1_ENCRYPTED
 * @return			encryption_payload_t object
 */
encryption_payload_t *encryption_payload_create(payload_type_t type);

#endif /** ENCRYPTION_PAYLOAD_H_ @}*/
