/**
 * @file initiator_init.h
 * 
 * @brief Interface of initiator_init_t.
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
 * @ingroup states
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
	 * 
	 * @param name 			name of the configuration
	 * @return				TODO
	 */
	status_t (*initiate_connection) (initiator_init_t *this, char *name);
	
	/**
	 * Retries to initiate a new connection with another dh_group_priority
	 * 
	 * @param this 				calling object
	 * @param dh_group_priority	dh group priority to try with
	 * @return					TODO
	 */
	status_t (*retry_initiate_connection) (initiator_init_t *this, int dh_group_priority);
};

/**
 * @brief Constructor of class initiator_init_t
 * 
 * @param ike_sa assigned IKE_SA
 * 
 * @ingroup states
 */
initiator_init_t *initiator_init_create(protected_ike_sa_t *ike_sa);


#endif /*INITIATOR_INIT_H_*/
