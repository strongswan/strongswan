/**
 * @file sa_payload.h
 * 
 * @brief Declaration of the class sa_payload_t. 
 * 
 * An object of this type represents an IKEv2 SA-Payload and contains proposal 
 * substructures.
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

#ifndef SA_PAYLOAD_H_
#define SA_PAYLOAD_H_

#include "../types.h"
#include "payload.h"
#include "proposal_substructure.h"
#include "../utils/linked_list.h"

/**
 * Critical flag must not be set
 */
#define SA_PAYLOAD_CRITICAL_FLAG FALSE;

/**
 * SA_PAYLOAD length in bytes without any proposal substructure
 */
#define SA_PAYLOAD_HEADER_LENGTH 4

/**
 * Object representing an IKEv2-SA Payload
 * 
 * The SA Payload format is described in RFC section 3.3.
 * 
 */
typedef struct sa_payload_s sa_payload_t;

struct sa_payload_s {
	/**
	 * implements payload_t interface
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Creates an iterator of stored proposal_substructure_t objects.
	 * 
	 * @warning The created iterator has to get destroyed by the caller!
	 *
	 * @param this 			calling sa_payload_t object
	 * @param iterator  		the created iterator is stored at the pointed pointer
	 * @param[in] forward 	iterator direction (TRUE: front to end)
	 * @return 		
	 * 						- SUCCESS or
	 * 						- OUT_OF_RES if iterator could not be created
	 */
	status_t (*create_proposal_substructure_iterator) (sa_payload_t *this,linked_list_iterator_t **iterator, bool forward);
	
	/**
	 * @brief Adds a proposal_substructure_t object to this object.
	 * 
	 * @warning The added proposal_substructure_t object  is 
	 * 			getting destroyed in destroy function of sa_payload_t.
	 *
	 * @param this 		calling sa_payload_t object
	 * @param proposal  proposal_substructure_t object to add
	 * @return 			- SUCCESS if succeeded
	 * 					- FAILED otherwise
	 */
	status_t (*add_proposal_substructure) (sa_payload_t *this,proposal_substructure_t *proposal);

	/**
	 * @brief Destroys an sa_payload_t object.
	 *
	 * @param this 	sa_payload_t object to destroy
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*destroy) (sa_payload_t *this);
};

/**
 * @brief Creates an empty sa_payload_t object
 * 
 * @return			
 * 					- created sa_payload_t object, or
 * 					- NULL if failed
 */
 
sa_payload_t *sa_payload_create();


#endif /*SA_PAYLOAD_H_*/
