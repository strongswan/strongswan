/**
 * @file sa_payload.h
 * 
 * @brief Interface of sa_payload_t.
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

#include <types.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/proposal_substructure.h>
#include <utils/linked_list.h>
#include <config/init_config.h>
#include <config/sa_config.h>

/**
 * Critical flag must not be set.
 * 
 * @ingroup payloads
 */
#define SA_PAYLOAD_CRITICAL_FLAG FALSE;

/**
 * SA_PAYLOAD length in bytes without any proposal substructure.
 * 
 * @ingroup payloads
 */
#define SA_PAYLOAD_HEADER_LENGTH 4

typedef struct sa_payload_t sa_payload_t;

/**
 * Class representing an IKEv2-SA Payload.
 * 
 * The SA Payload format is described in RFC section 3.3.
 * 
 * @ingroup payloads
 */
struct sa_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Creates an iterator of stored proposal_substructure_t objects.
	 * 
	 * @warning The created iterator has to get destroyed by the caller!
	 * 
	 * @warning When deleting an proposal using this iterator, 
	 * 			the length of this transform substructure has to be refreshed 
	 * 			by calling get_length()!
	 *
	 * @param this 			calling sa_payload_t object
	 * @param[in] forward 	iterator direction (TRUE: front to end)
	 * @return				created iterator_t object
	 */
	iterator_t *(*create_proposal_substructure_iterator) (sa_payload_t *this, bool forward);
	
	/**
	 * @brief Adds a proposal_substructure_t object to this object.
	 * 
	 * @warning The added proposal_substructure_t object  is 
	 * 			getting destroyed in destroy function of sa_payload_t.
	 *
	 * @param this 		calling sa_payload_t object
	 * @param proposal  proposal_substructure_t object to add
	 */
	void (*add_proposal_substructure) (sa_payload_t *this,proposal_substructure_t *proposal);
	
	/**
	 * Creates an array of ike_proposal_t's in this SA payload.
	 * 
	 * An IKE proposal consist of transform of type ENCRYPTION_ALGORITHM,
	 * PSEUDO_RANDOM_FUNCTION, INTEGRITY_ALGORITHM and DIFFIE_HELLMAN_GROUP
	 * 
	 * @param proposals			the pointer to the first entry of ike_proposal_t's is set
	 * @param proposal_count	the number of found proposals is written at this location
	 * @return
	 * 							- SUCCESS if an IKE proposal could be found
	 * 							- NOT_FOUND if no IKE proposal could be found
	 * 							- FAILED if a proposal does not contain all needed transforms
	 * 							  for a IKE_PROPOSAL 
	 */
	status_t (*get_ike_proposals) (sa_payload_t *this, ike_proposal_t **proposals, size_t *proposal_count);
	
	/**
	 * Creates an array of child_proposal_t's in this SA payload.
	 * 
	 * @param proposals			the pointer to the first entry of child_proposal_t's is set
	 * @param proposal_count	the number of found proposals is written at this location
	 * @return
	 * 							- SUCCESS if child proposals could be found
	 * 							- NOT_FOUND if no child proposal could be found
	 * 							- FAILED if a proposal does not contain all needed transforms
	 */
	status_t (*get_child_proposals) (sa_payload_t *this, child_proposal_t **proposals, size_t *proposal_count);	

	/**
	 * @brief Destroys an sa_payload_t object.
	 *
	 * @param this 	sa_payload_t object to destroy
	 */
	void (*destroy) (sa_payload_t *this);
};

/**
 * @brief Creates an empty sa_payload_t object
 * 
 * @return			created sa_payload_t object
 * 
 * @ingroup payloads
 */
sa_payload_t *sa_payload_create();

/**
 * @brief Creates a sa_payload_t object from array of ike_proposal_t's.
 * 
 * @return					created sa_payload_t object
 * @param proposals			pointer to first proposal in array of type ike_proposal_t
 * @param proposal_count	number of ike_proposal_t's in array
 * 
 * @ingroup payloads
 */
sa_payload_t *sa_payload_create_from_ike_proposals(ike_proposal_t *proposals, size_t proposal_count);

/**
 * @brief Creates a sa_payload_t object from array of child_proposal_t's.
 * 
 * @warning for proposals where AH and ESP is not set, an empty proposal is created.
 * 
 * 
 * @return					created sa_payload_t object
 * @param proposals			pointer to first proposal in array of type child_proposal_t
 * @param proposal_count	number of child_proposal_t's in array
 * 
 * @ingroup payloads
 */
sa_payload_t *sa_payload_create_from_child_proposals(child_proposal_t *proposals, size_t proposal_count);

#endif /*SA_PAYLOAD_H_*/
