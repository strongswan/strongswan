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
 * @brief This class represents an IKE_SA state when 
 * initializing a connection as initiator.
 * 
 * @b Constructors:
 *  - initiator_init_create() 
 * 
 * @ingroup states
 */
struct initiator_init_t {
	/**
	 * The state_t interface.
	 */
	state_t state_interface;
	
	/**
	 * Initiate a new connection with given connection_t object.
	 * 
	 * @param this 			calling object
	 * @param connection	connection to initiate
	 * @return				
	 * 						- SUCCESS
	 * 						- DELETE_ME if something failed
	 */
	status_t (*initiate_connection) (initiator_init_t *this, connection_t *connection);
	
	/**
	 * Retry to initiate a new connection with a specific dh_group_priority.
	 * 
	 * The dh_group_priority is starting at 1.
	 * 
	 * @param this 				calling object
	 * @param dh_group_priority	dh group priority to try with
	 * @return				
	 * 							- SUCCESS
	 * 							- DELETE_ME if something failed (see log for error)
	 */
	status_t (*retry_initiate_connection) (initiator_init_t *this, int dh_group_priority);
};

/**
 * @brief Constructor of class initiator_init_t.
 * 
 * @param ike_sa 	assigned IKE_SA
 * @return			created initiator_init_t object
 * 
 * @ingroup states
 */
initiator_init_t *initiator_init_create(protected_ike_sa_t *ike_sa);


#endif /*INITIATOR_INIT_H_*/
