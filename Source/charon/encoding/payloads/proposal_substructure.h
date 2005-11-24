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

#include <types.h>
#include <encoding/payloads/payload.h>
#include <encoding/payloads/transform_substructure.h>
#include <utils/linked_list.h>

/**
 * Length of the proposal substructure header
 * (without spi)
 */
#define PROPOSAL_SUBSTRUCTURE_HEADER_LENGTH 8


typedef enum protocol_id_t protocol_id_t;

/**
 * Protocol ID of a proposal
 */
enum protocol_id_t {
	UNDEFINED_PROTOCOL_ID = 201,
	IKE = 1,
	AH = 2,
	ESP = 3,
};         

typedef struct proposal_substructure_t proposal_substructure_t;

/**
 * Object representing an IKEv2- PROPOSAL SUBSTRUCTURE
 * 
 * The PROPOSAL SUBSTRUCTURE format is described in RFC section 3.3.1.
 * 
 */
struct proposal_substructure_t {
	/**
	 * implements payload_t interface
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
	 * @param iterator  		the created iterator is stored at the pointed pointer
	 * @param[in] forward 	iterator direction (TRUE: front to end)
	 * @return 		
	 * 						- SUCCESS or
	 * 						- OUT_OF_RES if iterator could not be created
	 */
	status_t (*create_transform_substructure_iterator) (proposal_substructure_t *this,linked_list_iterator_t **iterator, bool forward);
	
	/**
	 * @brief Adds a transform_substructure_t object to this object.
	 * 
	 * @warning The added transform_substructure_t object  is 
	 * 			getting destroyed in destroy function of proposal_substructure_t.
	 *
	 * @param this 		calling proposal_substructure_t object
	 * @param transform transform_substructure_t object to add
	 * @return 			- SUCCESS if succeeded
	 * 					- FAILED otherwise
	 */
	status_t (*add_transform_substructure) (proposal_substructure_t *this,transform_substructure_t *transform);
	
	/**
	 * @brief Sets the proposal number of current proposal.
	 *
	 * @param this 		calling proposal_substructure_t object
	 * @param id			proposal number to set
	 * @return 			- SUCCESS
	 */
	status_t (*set_proposal_number) (proposal_substructure_t *this,u_int8_t proposal_number);
	
	/**
	 * @brief get proposal number of current proposal.
	 * 
	 * @param this 		calling proposal_substructure_t object
	 * @return 			proposal number of current proposal substructure.
	 */
	u_int8_t (*get_proposal_number) (proposal_substructure_t *this);

	/**
	 * @brief Sets the protocol id of current proposal.
	 *
	 * @param this 		calling proposal_substructure_t object
	 * @param id			protocol id to set
	 * @return 			- SUCCESS
	 */
	status_t (*set_protocol_id) (proposal_substructure_t *this,u_int8_t protocol_id);
	
	/**
	 * @brief get protocol id of current proposal.
	 * 
	 * @param this 		calling proposal_substructure_t object
	 * @return 			protocol id of current proposal substructure.
	 */
	u_int8_t (*get_protocol_id) (proposal_substructure_t *this);


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
	 * @return 		
	 * 				- SUCCESS or
	 * 				- OUT_OF_RES
	 */
	status_t (*set_spi) (proposal_substructure_t *this, chunk_t spi);

	/**
	 * @brief Clones an proposal_substructure_t object.
	 *
	 * @param this 	proposal_substructure_t object to clone
	 * @param clone	cloned object will be written there
	 * @return 		
	 * 				- SUCCESS
	 * 				- OUT_OF_RES
	 */
	status_t (*clone) (proposal_substructure_t *this,proposal_substructure_t **clone);

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
