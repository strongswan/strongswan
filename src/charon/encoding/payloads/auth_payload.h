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

/**
 * @defgroup auth_payload auth_payload
 * @{ @ingroup payloads
 */

#ifndef AUTH_PAYLOAD_H_
#define AUTH_PAYLOAD_H_

typedef struct auth_payload_t auth_payload_t;

#include <library.h>
#include <encoding/payloads/payload.h>
#include <sa/authenticators/authenticator.h>

/**
 * Length of a auth payload without the auth data in bytes.
 */
#define AUTH_PAYLOAD_HEADER_LENGTH 8

/**
 * Class representing an IKEv2 AUTH payload.
 *
 * The AUTH payload format is described in RFC section 3.8.
 */
struct auth_payload_t {
	
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Set the AUTH method.
	 *
	 * @param method		auth_method_t to use
	 */
	void (*set_auth_method) (auth_payload_t *this, auth_method_t method);
	
	/**
	 * Get the AUTH method.
	 *
	 * @return				auth_method_t used
	 */
	auth_method_t (*get_auth_method) (auth_payload_t *this);
	
	/**
	 * Set the AUTH data.
	 * 
	 * Data gets cloned.
	 *
	 * @param data			AUTH data as chunk_t
	 */
	void (*set_data) (auth_payload_t *this, chunk_t data);
	
	/**
	 * Get the AUTH data.
	 * 
	 * Returned data are a copy of the internal one.
	 *
	 * @return				AUTH data as chunk_t
	 */
	chunk_t (*get_data_clone) (auth_payload_t *this);
	
	/**
	 * Get the AUTH data.
	 * 
	 * Returned data are NOT copied
	 *
	 * @return				AUTH data as chunk_t
	 */
	chunk_t (*get_data) (auth_payload_t *this);
	
	/**
	 * Destroys an auth_payload_t object.
	 */
	void (*destroy) (auth_payload_t *this);
};

/**
 * Creates an empty auth_payload_t object.
 * 
 * @return auth_payload_t object
 */
auth_payload_t *auth_payload_create(void);

#endif /** AUTH_PAYLOAD_H_ @}*/
