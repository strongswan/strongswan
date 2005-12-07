/**
 * @file responder_init.h
 * 
 * @brief Interface of responder_init_t.
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

#ifndef RESPONDER_INIT_H_
#define RESPONDER_INIT_H_

#include <sa/ike_sa.h>
#include <sa/states/state.h>


typedef struct responder_init_t responder_init_t;

/**
 * @brief This class represents an IKE_SA state when 
 * initializing a connection as responder.
 * 
 * @b Constructors:
 *  - responder_init_create()
 * 
 * @ingroup states
 */
struct responder_init_t {
	/**
	 * The state_t interface.
	 */
	state_t state_interface;
};

/**
 * Constructor of class responder_init_t.
 * 
 * The following functions of the assigned protected_ike_sa_t object are being called with 
 * valid values after successfully processing a received message and before changing
 * to next state IKE_SA_INIT_RESPONDED:
 *  - protected_ike_sa_t.set_init_config()
 *  - protected_ike_sa_t.set_my_host()
 *  - protected_ike_sa_t.set_other_host()
 *  - protected_ike_sa_t.compute_secrets()
 *  - protected_ike_sa_t.create_transforms_from_proposal()
 * 
 * @param ike_sa 	assigned IKE_SA
 * 
 * @return 			responder_init_t object
 * 
 * @ingroup states
 */
responder_init_t *responder_init_create(protected_ike_sa_t *ike_sa);

#endif /*RESPONDER_INIT_H_*/
