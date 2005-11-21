/**
 * @file ike_sa_established.h
 * 
 * @brief State of an established IKE_SA.
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

#ifndef IKE_SA_ESTABLISHED_H_
#define IKE_SA_ESTABLISHED_H_

#include "state.h"

/**
 * @brief This class represents an the state of an established
 * IKE_SA.
 *
 */
typedef struct ike_sa_established_s ike_sa_established_t;

struct ike_sa_established_s {
	/**
	 * methods of the state_t interface
	 */
	state_t state_interface;

};

/**
 * Constructor of class ike_sa_established_t
 */
ike_sa_established_t *ike_sa_established_create();

#endif /*IKE_SA_ESTABLISHED_H_*/
