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
 *
 * $Id$
 */

/**
 * @defgroup proposal_substructure proposal_substructure
 * @{ @ingroup payloads
 */

#ifndef PROPOSAL_SUBSTRUCTURE_H_
#define PROPOSAL_SUBSTRUCTURE_H_

typedef struct proposal_substructure_t proposal_substructure_t;

#include <library.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/transform_substructure.h>
#include <config/proposal.h>
#include <utils/linked_list.h>


/**
 * Length of the proposal substructure header (without spi).
 */
#define PROPOSAL_SUBSTRUCTURE_HEADER_LENGTH 8

/**
 * Class representing an IKEv2-PROPOSAL SUBSTRUCTURE.
 * 
 * The PROPOSAL SUBSTRUCTURE format is described in RFC section 3.3.1.
 */
struct proposal_substructure_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Creates an iterator of stored transform_substructure_t objects.
	 *
	 * @param forward		iterator direction (TRUE: front to end)
	 * @return				created iterator_t object
	 */
	iterator_t *(*create_transform_substructure_iterator) (
								proposal_substructure_t *this, bool forward);
	
	/**
	 * Adds a transform_substructure_t object to this object.
	 *
	 * @param transform 	transform_substructure_t object to add
	 */
	void (*add_transform_substructure) (proposal_substructure_t *this,
										transform_substructure_t *transform);
	
	/**
	 * Sets the proposal number of current proposal.
	 *
	 * @param id			proposal number to set
	 */
	void (*set_proposal_number) (proposal_substructure_t *this,
								 u_int8_t proposal_number);
	
	/**
	 * get proposal number of current proposal.
	 * 
	 * @return 			proposal number of current proposal substructure.
	 */
	u_int8_t (*get_proposal_number) (proposal_substructure_t *this);

	/**
	 * get the number of transforms in current proposal.
	 * 
	 * @return 			transform count in current proposal
	 */
	size_t (*get_transform_count) (proposal_substructure_t *this);

	/**
	 * get size of the set spi in bytes.
	 * 
	 * @return 			size of the spi in bytes
	 */
	size_t (*get_spi_size) (proposal_substructure_t *this);

	/**
	 * Sets the protocol id of current proposal.
	 *
	 * @param id		protocol id to set
	 */
	void (*set_protocol_id) (proposal_substructure_t *this,
							 u_int8_t protocol_id);
	
	/**
	 * get protocol id of current proposal.
	 * 
	 * @return 			protocol id of current proposal substructure.
	 */
	u_int8_t (*get_protocol_id) (proposal_substructure_t *this);
	
	/**
	 * Sets the next_payload field of this substructure
	 * 
	 * If this is the last proposal, next payload field is set to 0,
	 * otherwise to 2
	 *
	 * @param is_last	When TRUE, next payload field is set to 0, otherwise to 2
	 */
	void (*set_is_last_proposal) (proposal_substructure_t *this, bool is_last);
	
	/**
	 * Returns the currently set SPI of this proposal.
	 *
	 * @return 			chunk_t pointing to the value
	 */
	chunk_t (*get_spi) (proposal_substructure_t *this);
	
	/**
	 * Sets the SPI of the current proposal.
	 * 	
	 * @warning SPI is getting copied
	 * 
	 * @param spi		chunk_t pointing to the value to set
	 */
	void (*set_spi) (proposal_substructure_t *this, chunk_t spi);
	
	/**
	 * Get a proposal_t from the propsal_substructure_t.
	 * 
	 * @return			proposal_t
	 */
	proposal_t * (*get_proposal) (proposal_substructure_t *this);

	/**
	 * Clones an proposal_substructure_t object.
	 *
	 * @return		cloned object
	 */
	proposal_substructure_t* (*clone) (proposal_substructure_t *this);

	/**
	 * Destroys an proposal_substructure_t object.
	 */
	void (*destroy) (proposal_substructure_t *this);
};

/**
 * Creates an empty proposal_substructure_t object
 * 
 * @return proposal_substructure_t object
 */
proposal_substructure_t *proposal_substructure_create(void);

/**
 * Creates a proposal_substructure_t from a proposal_t.
 *
 * @param proposal		proposal to build a substruct out of it
 * @return 				proposal_substructure_t object
 */
proposal_substructure_t *proposal_substructure_create_from_proposal(
														proposal_t *proposal);

#endif /*PROPOSAL_SUBSTRUCTURE_H_ @} */
