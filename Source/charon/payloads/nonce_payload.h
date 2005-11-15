/**
 * @file nonce_payload.h
 * 
 * @brief Declaration of the class nonce_payload_t. 
 * 
 * An object of this type represents an IKEv2 Nonce-Payload.
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

#ifndef NONCE_PAYLOAD_H_
#define NONCE_PAYLOAD_H_

#include "../types.h"
#include "payload.h"



/**
 * Object representing an IKEv2 Nonce payload
 * 
 * The Nonce payload format is described in draft section 3.3.
 * 
 */
typedef struct nonce_payload_s nonce_payload_t;

struct nonce_payload_s {
	/**
	 * implements payload_t interface
	 */
	payload_t payload_interface;

	/**
	 * @brief Set the nonce value.
	 *
	 * @param this 			calling nonce_payload_t object
	 * @param nonce	  		chunk containing the nonce, will be cloned
	 * @return 				SUCCESS in any case
	 */
	status_t (*set_nonce) (nonce_payload_t *this, chunk_t nonce);
	
	/**
	 * @brief Get the nonce value.
	 *
	 * @param this 			calling nonce_payload_t object
	 * @param[out] nonce	chunk where the cloned nonce data is located
	 * @return 				SUCCESS in any case
	 */
	status_t (*get_nonce) (nonce_payload_t *this, chunk_t *nonce);

	/**
	 * @brief Destroys an nonce_payload_t object.
	 *
	 * @param this 	nonce_payload_t object to destroy
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*destroy) (nonce_payload_t *this);
};

/**
 * @brief Creates an empty nonce_payload_t object
 * 
 * @return			
 * 					- created nonce_payload_t object, or
 * 					- NULL if failed
 */
 
nonce_payload_t *nonce_payload_create();


#endif /*NONCE_PAYLOAD_H_*/
