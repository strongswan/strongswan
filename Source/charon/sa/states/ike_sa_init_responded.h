/**
 * @file ike_sa_init_responded.h
 * 
 * @brief Interface of ike_sa_init_responded_t.
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

#ifndef IKE_SA_INIT_RESPONDED_H_
#define IKE_SA_INIT_RESPONDED_H_

#include <sa/ike_sa.h>
#include <sa/states/state.h>

typedef struct ike_sa_init_responded_t ike_sa_init_responded_t;

/**
 * @brief This class represents an IKE_SA state when 
 * responded to an IKE_SA_INIT request.
 * 
 * The state accpets IKE_AUTH requests. It proves the authenticity
 * and sets up the first child sa. Then it sends back an IKE_AUTH
 * reply and changes to the IKE_SA_ESTABLISHED state.
 * 
 * @b Constructors:
 *  - ike_sa_init_response_data()
 * 
 * @todo Implement handling of SET_WINDOW_SIZE notify
 * 
 * @todo Implement handling of INITIAL_CONTACT notify
 * 
 * @ingroup states
 */
struct ike_sa_init_responded_t {
	/**
	 * The state_t interface.
	 */
	state_t state_interface;

};

/**
 * @brief Constructor of class ike_sa_init_responded_t
 * 
 * @param ike_sa 						assigned IKE_SA
 * @param received_nonce				received nonce data in IKE_SA_INIT request
 * @param sent_nonce					sent nonce data in IKE_SA_INIT response
 * @param ike_sa_init_request_data		binary representation of received IKE_SA_INIT request
 * @param ike_sa_init_response_data		binary representation of sent IKE_SA_INIT response
 * 
 * @ingroup states
 */
ike_sa_init_responded_t *ike_sa_init_responded_create(protected_ike_sa_t *ike_sa,
														chunk_t received_nonce,
														chunk_t sent_nonce,
														chunk_t ike_sa_init_request_data,
														chunk_t ike_sa_init_response_data);

#endif /*IKE_SA_INIT_RESPONDED_H_*/
