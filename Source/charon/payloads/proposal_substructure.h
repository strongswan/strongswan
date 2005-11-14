/**
 * @file proposal_substructure.h
 * 
 * @brief Declaration of the class proposal_substructure_t. 
 * 
 * An object of this type represents an IKEv2 PROPOSAL Substructure and contains transforms.
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

#ifndef PROPOSAL_SUBSTRUCTURE_H_
#define PROPOSAL_SUBSTRUCTURE_H_


#include "../types.h"
#include "payload.h"

/**
 * Object representing an IKEv2- PROPOSAL SUBSTRUCTURE
 * 
 * The PROPOSAL SUBSTRUCTURE format is described in RFC section 3.3.1.
 * 
 */
typedef struct proposal_substructure_s proposal_substructure_t;

struct proposal_substructure_s {
	/**
	 * implements payload_t interface
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Destroys an proposal_substructure_t object.
	 *
	 * @param this 	proposal_substructure_t object to destroy
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*destroy) (proposal_substructure_t *this);
};

/**
 * @brief Creates an empty proposal_substructure_t object
 * 
 * @return			
 * 					- created proposal_substructure_t object, or
 * 					- NULL if failed
 */
 
proposal_substructure_t *proposal_substructure_create();



#endif /*PROPOSAL_SUBSTRUCTURE_H_*/
