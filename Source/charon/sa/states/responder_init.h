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
 * @brief This class represents an IKE_SA state when initializing.
 * a connection as responder.
 *
 */
struct responder_init_t {
	/**
	 * methods of the state_t interface
	 */
	state_t state_interface;

};

/**
 * Constructor of class responder_init_t
 * 
 * @param ike_sa assigned IKE_SA
 * 
 * @return responder_init state
 */
responder_init_t *responder_init_create(protected_ike_sa_t *ike_sa);

#endif /*RESPONDER_INIT_H_*/
