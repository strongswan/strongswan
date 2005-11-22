/**
 * @file ike_sa_init_responded.h
 * 
 * @brief State of a IKE_SA after responding to an IKE_SA_INIT request
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

#include "state.h"

#include "../ike_sa.h"

/**
 * @brief This class represents an IKE_SA state when responded to an IKE_SA_INIT request
 *
 */
typedef struct ike_sa_init_responded_s ike_sa_init_responded_t;

struct ike_sa_init_responded_s {
	/**
	 * methods of the state_t interface
	 */
	state_t state_interface;

};

/**
 * Constructor of class ike_sa_init_responded_t
 * 
 * @param ike_sa assigned IKE_SA
 */
ike_sa_init_responded_t *ike_sa_init_responded_create(protected_ike_sa_t *ike_sa, chunk_t shared_secret, chunk_t received_nonce, chunk_t sent_nonce);

#endif /*IKE_SA_INIT_RESPONDED_H_*/
