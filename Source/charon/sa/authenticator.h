/**
 * @file authenticator.h
 *
 * @brief Interface of authenticator.
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


#ifndef _AUTHENTICATOR_H_
#define _AUTHENTICATOR_H_


#include <types.h>
#include <encoding/payloads/auth_payload.h>
#include <utils/identification.h>
#include <sa/ike_sa.h>


typedef struct authenticator_t authenticator_t;


/**
 * @brief Class authenticator_t. Used to authenticate a peer.
 * 
 * Currently only preshared secret as auth_method supported!
 * 
 * @ingroup sa
 */
struct authenticator_t {

	/**
	 * @brief Verifying of given authentication data.
	 *
	 * TODO
	 * @param this 			authenticator_t object
	 * @return
	 * 						- NOT_SUPPORTED if auth_method is not supported
	 */
	status_t (*verify_authentication) (authenticator_t *this,auth_method_t auth_method, chunk_t auth_data, chunk_t last_message, chunk_t other_nonce,identification_t *my_id,bool *verified);

	/**
	 * @brief Verifying of given authentication data.
	 *
	 * TODO
	 * @param this 			authenticator_t object
	 * @return
	 * 						- NOT_SUPPORTED if auth_method is not supported
	 */
	status_t (*allocate_auth_data) (authenticator_t *this,auth_method_t auth_method,chunk_t last_message, chunk_t other_nonce,identification_t *my_id,chunk_t *auth_data);


	/**
	 * @brief Destroys a authenticator_t object.
	 *
	 * @param this 			authenticator_t object
	 */
	void (*destroy) (authenticator_t *this);
};

authenticator_t *authenticator_create(protected_ike_sa_t *ike_sa);

#endif //_AUTHENTICATOR_H_
