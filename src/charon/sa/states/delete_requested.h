/**
 * @file delete_requested.h
 * 
 * @brief Interface of delete_requested_t.
 * 
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#ifndef DELETE_REQUESTED_H_
#define DELETE_REQUESTED_H_

#include <sa/states/state.h>
#include <sa/ike_sa.h>

typedef struct delete_requested_t delete_requested_t;

/**
 * @brief This class represents an the state of a half closed IKE_SA.
 * 
 * @b Constructors:
 * - delete_requested_create()
 * 
 * @ingroup states
 */
struct delete_requested_t {
	/**
	 * methods of the state_t interface
	 */
	state_t state_interface;

};

/**
 * @brief Constructor of class delete_requested_t
 * 
 * @param ike_sa 	assigned ike_sa
 * @return			created delete_requested_t object
 * 
 * @ingroup states
 */
delete_requested_t *delete_requested_create(protected_ike_sa_t *ike_sa);

#endif /*DELETE_REQUESTED_H_*/
