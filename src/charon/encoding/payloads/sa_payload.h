/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

/**
 * @defgroup sa_payload sa_payload
 * @{ @ingroup payloads
 */

#ifndef SA_PAYLOAD_H_
#define SA_PAYLOAD_H_

typedef struct sa_payload_t sa_payload_t;

#include <library.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/proposal_substructure.h>
#include <utils/linked_list.h>

/**
 * SA_PAYLOAD length in bytes without any proposal substructure.
 */
#define SA_PAYLOAD_HEADER_LENGTH 4

/**
 * Class representing an IKEv2-SA Payload.
 *
 * The SA Payload format is described in RFC section 3.3.
 */
struct sa_payload_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;
	
	/**
	 * Creates an iterator of stored proposal_substructure_t objects.
	 * 
	 * When deleting an proposal using this iterator, 
	 * the length of this transform substructure has to be refreshed 
	 * by calling get_length()!
	 *
	 * @param forward 		iterator direction (TRUE: front to end)
	 * @return				created iterator_t object
	 */
	iterator_t *(*create_proposal_substructure_iterator) (sa_payload_t *this,
														  bool forward);
	
	/**
	 * Adds a proposal_substructure_t object to this object.
	 *
	 * @param proposal  		proposal_substructure_t object to add
	 */
	void (*add_proposal_substructure) (sa_payload_t *this,
									   proposal_substructure_t *proposal);

	/**
	 * Gets the proposals in this payload as a list.
	 * 
	 * @return					a list containing proposal_t s
	 */
	linked_list_t *(*get_proposals) (sa_payload_t *this);
	
	/**
	 * Add a child proposal (AH/ESP) to the payload.
	 * 
	 * @param proposal			child proposal to add to the payload
	 */
	void (*add_proposal) (sa_payload_t *this, proposal_t *proposal);
	
	/**
	 * Destroys an sa_payload_t object.
	 */
	void (*destroy) (sa_payload_t *this);
};

/**
 * Creates an empty sa_payload_t object
 * 
 * @return					created sa_payload_t object
 */
sa_payload_t *sa_payload_create(void);

/**
 * Creates a sa_payload_t object from a list of proposals.
 * 
 * @param proposals			list of proposals to build the payload from
 * @return					sa_payload_t object
 */
sa_payload_t *sa_payload_create_from_proposal_list(linked_list_t *proposals);

/**
 * Creates a sa_payload_t object from a single proposal.
 * 
 * This is only for convenience. Use sa_payload_create_from_proposal_list
 * if you want to add more than one proposal.
 * 
 * @param proposal			proposal from which the payload should be built.
 * @return					sa_payload_t object
 */
sa_payload_t *sa_payload_create_from_proposal(proposal_t *proposal);

#endif /** SA_PAYLOAD_H_ @}*/
