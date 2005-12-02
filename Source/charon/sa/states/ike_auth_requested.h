/**
 * @file ike_auth_requested.h
 * 
 * @brief Interface of ike_auth_requested_t.
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

#ifndef IKE_AUTH_REQUESTED_H_
#define IKE_AUTH_REQUESTED_H_

#include <sa/states/state.h>
#include <sa/ike_sa.h>


typedef struct ike_auth_requested_t ike_auth_requested_t;

/**
 * @brief This class represents an IKE_SA, which has requested an IKE_AUTH.
 * 
 * The state accpets IKE_AUTH responses. It proves the authenticity
 * and sets up the first child sa. After that, it processes to the 
 * IKE_SA_ESTABLISHED state.
 * 
 * @ingroup states
 */
struct ike_auth_requested_t {
	/**
	 * methods of the state_t interface
	 */
	state_t state_interface;

};

/**
 * Constructor of class ike_auth_requested_t
 * 
 * @param ike_sa		assigned ike_sa object
 * @param sent_nonce	Sent nonce value
 * @param received_nonce	Received nonce value
 * @return				created ike_auth_requested_t object
 * 
 * @ingroup states
 */
ike_auth_requested_t *ike_auth_requested_create(protected_ike_sa_t *ike_sa);

#endif /*IKE_AUTH_REQUESTED_H_*/
