/**
 * @file auth_payload.h
 * 
 * @brief Interface of auth_payload_t.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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


#ifndef _AUTH_PAYLOAD_H_
#define _AUTH_PAYLOAD_H_

#include <types.h>
#include <encoding/payloads/payload.h>

/**
 * Length of a auth payload without the auth data in bytes.
 * 
 * @ingroup payloads
 */
#define AUTH_PAYLOAD_HEADER_LENGTH 8


typedef enum auth_method_t auth_method_t;

/**
 * AUTH Method of a AUTH payload.
 * 
 * @ingroup payloads
 */
enum auth_method_t {
	/**
	 * Computed as specified in section 2.15 of draft using 
	 * an RSA private key over a PKCS#1 padded hash.
	 */
	RSA_DIGITAL_SIGNATURE = 1,
	
	/* Computed as specified in
     * section 2.15 of draft using the shared key associated with the identity
     * in the ID payload and the negotiated prf function
     */
	SHARED_KEY_MESSAGE_INTEGRITY_CODE = 2,
	
	/* Computed as specified in section
     * 2.15 of draft using a DSS private key over a SHA-1 hash.
     */
    DSS_DIGITAL_SIGNATURE = 3,
};

/**
 * string mappings for auth method.
 * 
 * @ingroup payloads
 */
extern mapping_t auth_method_m[];


typedef struct auth_payload_t auth_payload_t;

/**
 * @brief Object representing an IKEv2 AUTH payload.
 * 
 * The AUTH payload format is described in draft section 3.8.
 * 
 * @b Constructors:
 * - auth_payload_create()
 * 
 * @ingroup payloads
 */
struct auth_payload_t {
	
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * @brief Set the AUTH method.
	 *
	 * @param this 			calling auth_payload_t object
	 * @param method		auth_method_t to use
	 */
	void (*set_auth_method) (auth_payload_t *this, auth_method_t method);
	
	/**
	 * @brief Get the AUTH method.
	 *
	 * @param this 			calling auth_payload_t object
	 * @return				auth_method_t used
	 */
	auth_method_t (*get_auth_method) (auth_payload_t *this);
	
	/**
	 * @brief Set the AUTH data.
	 * 
	 * Data are getting cloned.
	 *
	 * @param this 			calling auth_payload_t object
	 * @param data			AUTH data as chunk_t
	 */
	void (*set_data) (auth_payload_t *this, chunk_t data);
	
	/**
	 * @brief Get the AUTH data.
	 * 
	 * Returned data are a copy of the internal one.
	 *
	 * @param this 			calling auth_payload_t object
	 * @return				AUTH data as chunk_t
	 */
	chunk_t (*get_data_clone) (auth_payload_t *this);
	
	/**
	 * @brief Get the AUTH data.
	 * 
	 * Returned data are NOT copied
	 *
	 * @param this 			calling auth_payload_t object
	 * @return				AUTH data as chunk_t
	 */
	chunk_t (*get_data) (auth_payload_t *this);
	
	/**
	 * @brief Destroys an auth_payload_t object.
	 *
	 * @param this 			auth_payload_t object to destroy
	 */
	void (*destroy) (auth_payload_t *this);
};

/**
 * @brief Creates an empty auth_payload_t object.
 * 
 * @return auth_payload_t object
 * 
 * @ingroup payloads
 */
auth_payload_t *auth_payload_create();


#endif //_AUTH_PAYLOAD_H_
