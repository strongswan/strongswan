/**
 * @file proposal_substructure.h
 * 
 * @brief Interface of proposal_substructure_t.
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

#include <types.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/transform_substructure.h>
#include <utils/linked_list.h>

/**
 * IKEv1 Value for a proposal payload.
 * 
 * @ingroup payloads
 */
#define PROPOSAL_TYPE_VALUE 2

/**
 * Length of the proposal substructure header
 * (without spi).
 * 
 * @ingroup payloads
 */
#define PROPOSAL_SUBSTRUCTURE_HEADER_LENGTH 8


typedef enum protocol_id_t protocol_id_t;

/**
 * Protocol ID of a proposal.
 * 
 * @ingroup payloads
 */
enum protocol_id_t {
	UNDEFINED_PROTOCOL_ID = 201,
	IKE = 1,
	AH = 2,
	ESP = 3,
};

/** 
 * String mappings for protocol_id_t.
 */
extern mapping_t protocol_id_m[];

typedef struct proposal_substructure_t proposal_substructure_t;

/**
 * Object representing an IKEv2-PROPOSAL SUBSTRUCTURE.
 * 
 * The PROPOSAL SUBSTRUCTURE format is described in RFC section 3.3.1.
 * 
 * @ingroup payloads
 */
struct proposal_substructure_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * @brief Creates an iterator of stored transform_substructure_t objects.
	 * 
	 * @warning The created iterator has to get destroyed by the caller!
	 * 			When deleting any transform over this iterator, call 
	 * 			get_size to make sure the length and number values are ok.
	 *
	 * @param this 			calling proposal_substructure_t object
	 * @param[in] forward 	iterator direction (TRUE: front to end)
	 * @return				created iterator_t object
	 */
	iterator_t * (*create_transform_substructure_iterator) (proposal_substructure_t *this, bool forward);
	
	/**
	 * @brief Adds a transform_substructure_t object to this object.
	 * 
	 * @warning The added transform_substructure_t object  is 
	 * 			getting destroyed in destroy function of proposal_substructure_t.
	 *
	 * @param this 		calling proposal_substructure_t object
	 * @param transform transform_substructure_t object to add
	 */
	void (*add_transform_substructure) (proposal_substructure_t *this,transform_substructure_t *transform);
	
	/**
	 * @brief Sets the proposal number of current proposal.
	 *
	 * @param this 		calling proposal_substructure_t object
	 * @param id			proposal number to set
	 */
	void (*set_proposal_number) (proposal_substructure_t *this,u_int8_t proposal_number);
	
	/**
	 * @brief get proposal number of current proposal.
	 * 
	 * @param this 		calling proposal_substructure_t object
	 * @return 			proposal number of current proposal substructure.
	 */
	u_int8_t (*get_proposal_number) (proposal_substructure_t *this);

	/**
	 * @brief get the number of transforms in current proposal.
	 * 
	 * @param this 		calling proposal_substructure_t object
	 * @return 			transform count in current proposal
	 */
	size_t (*get_transform_count) (proposal_substructure_t *this);

	/**
	 * @brief get size of the set spi in bytes.
	 * 
	 * @param this 		calling proposal_substructure_t object
	 * @return 			size of the spi in bytes
	 */
	size_t (*get_spi_size) (proposal_substructure_t *this);

	/**
	 * @brief Sets the protocol id of current proposal.
	 *
	 * @param this 		calling proposal_substructure_t object
	 * @param id			protocol id to set
	 */
	void (*set_protocol_id) (proposal_substructure_t *this,u_int8_t protocol_id);
	
	/**
	 * @brief get protocol id of current proposal.
	 * 
	 * @param this 		calling proposal_substructure_t object
	 * @return 			protocol id of current proposal substructure.
	 */
	u_int8_t (*get_protocol_id) (proposal_substructure_t *this);
	
	/**
	 * @brief Get informations for a specific transform type. 
	 * 
	 * @param this 			calling proposal_substructure_t object
	 * @param type			type to get informations for
	 * @param transform_id 	transform id of the specific type
	 * @param key_length 	key length of the specific key length transform attribute
	 * @return 			
	 * 						- SUCCESS if transform type is part of this proposal and 
	 * 					 	 all data (incl. key length) could be fetched
	 * 						- NOT_FOUND if transform type is not part of this proposal
	 */
	status_t (*get_info_for_transform_type) (proposal_substructure_t *this,transform_type_t type, u_int16_t *transform_id, u_int16_t *key_length);

	/**
	 * @brief Sets the next_payload field of this substructure
	 * 
	 * If this is the last proposal, next payload field is set to 0,
	 * otherwise to 2
	 *
	 * @param this 		calling proposal_substructure_t object
	 * @param is_last	When TRUE, next payload field is set to 0, otherwise to 2
	 */
	void (*set_is_last_proposal) (proposal_substructure_t *this, bool is_last);

	/**
	 * @brief Returns the currently set SPI of this proposal.
	 * 	
	 * @warning Returned data are not copied
	 * 
	 * @param this 	calling proposal_substructure_t object
	 * @return 		chunk_t pointing to the value
	 */
	chunk_t (*get_spi) (proposal_substructure_t *this);
	
	/**
	 * @brief Sets the SPI of the current proposal.
	 * 	
	 * @warning SPI is getting copied
	 * 
	 * @param this 	calling proposal_substructure_t object
	 * @param spi	chunk_t pointing to the value to set
	 */
	void (*set_spi) (proposal_substructure_t *this, chunk_t spi);

	/**
	 * @brief Clones an proposal_substructure_t object.
	 *
	 * @param this 	proposal_substructure_t object to clone
	 * @return		cloned object
	 */
	proposal_substructure_t* (*clone) (proposal_substructure_t *this);

	/**
	 * @brief Destroys an proposal_substructure_t object.
	 *
	 * @param this 	proposal_substructure_t object to destroy
	 */
	void (*destroy) (proposal_substructure_t *this);
};

/**
 * @brief Creates an empty proposal_substructure_t object
 * 
 * @return			created proposal_substructure_t object
 * 
 * @ingroup payloads
 */
proposal_substructure_t *proposal_substructure_create();



#endif /*PROPOSAL_SUBSTRUCTURE_H_*/
