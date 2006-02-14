/**
 * @file ike_sa_init_requested.h
 * 
 * @brief Interface of ike_sa_init_requestet_t.
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
 

#ifndef IKE_SA_INIT_REQUESTED_H_
#define IKE_SA_INIT_REQUESTED_H_

#include <types.h>
#include <sa/ike_sa.h>
#include <sa/states/state.h>
#include <transforms/diffie_hellman.h>

typedef struct ike_sa_init_requested_t ike_sa_init_requested_t;

/**
 * @brief This class represents an IKE_SA state when 
 * requested an IKE_SA_INIT as initiator.
 * 
 * @b Constructors:
 *  - ike_sa_init_requested_create()
 * 
 * @todo Include valid child sa SPIs in proposal
 * 
 * @ingroup states
 */
struct ike_sa_init_requested_t {
	/**
	 * The state_t interface.
	 */
	state_t state_interface;
};

/**
 * Constructor of class ike_sa_init_requested_t.
 * 
 * @param ike_sa 					assigned ike_sa
 * @param diffie_hellman			diffie_hellman object use to retrieve shared secret
 * @param sent_nonce				Sent nonce value
 * @param ike_sa_init_request_data	the binary representation of the IKE_SA_INIT request message
 * @return							created ike_sa_init_request_t object
 * 
 * @ingroup states
 */
ike_sa_init_requested_t *ike_sa_init_requested_create(protected_ike_sa_t *ike_sa,
														diffie_hellman_t *diffie_hellman,
														chunk_t sent_nonce,
														chunk_t ike_sa_init_request_data);

#endif /*IKE_SA_INIT_REQUESTED_H_*/
