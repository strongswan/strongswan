/**
 * @file ike_auth_requested.h
 * 
 * @brief State of an IKE_SA, which has requested an IKE_AUTH.
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

#include <states/state.h>
#include <ike_sa.h>

/**
 * @brief This class represents an IKE_SA, which has requested an IKE_AUTH.
 *
 */
typedef struct ike_auth_requested_s ike_auth_requested_t;

struct ike_auth_requested_s {
	/**
	 * methods of the state_t interface
	 */
	state_t state_interface;

};

/**
 * Constructor of class ike_auth_requested_t
 * 
 * @param ike_sa		assigned ike_sa object
 */
ike_auth_requested_t *ike_auth_requested_create(protected_ike_sa_t *ike_sa);

#endif /*IKE_AUTH_REQUESTED_H_*/
