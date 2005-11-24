/**
 * @file initiator_init.h
 * 
 * @brief Start state of a IKE_SA as initiator
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


#ifndef INITIATOR_INIT_H_
#define INITIATOR_INIT_H_

#include <sa/ike_sa.h>
#include <sa/states/state.h>


typedef struct initiator_init_t initiator_init_t;

/**
 * @brief This class represents an IKE_SA state when initializing.
 * a connection as initiator
 *
 */
struct initiator_init_t {
	/**
	 * methods of the state_t interface
	 */
	state_t state_interface;
	
	/**
	 * Initiate a new connection with given configuration name
	 * 
	 * @param this 			calling object
	 * @param name 			name of the configuration
	 * @param new_state		new state if call succeeded
	 * @return				TODO
	 */
	status_t (*initiate_connection) (initiator_init_t *this, char *name, state_t **new_state);	
};

/**
 * Constructor of class initiator_init_t
 * 
 * @param ike_sa assigned IKE_SA
 */
initiator_init_t *initiator_init_create(protected_ike_sa_t *ike_sa);


#endif /*INITIATOR_INIT_H_*/
