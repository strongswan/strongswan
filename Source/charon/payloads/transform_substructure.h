/**
 * @file transform_substructure.h
 * 
 * @brief Declaration of the class transform_substructure_t. 
 * 
 * An object of this type represents an IKEv2 TRANSFORM Substructure and contains Attributes.
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

#ifndef TRANSFORM_SUBSTRUCTURE_H_
#define TRANSFORM_SUBSTRUCTURE_H_

#include "../types.h"
#include "payload.h"
#include "../utils/linked_list.h"
#include "transform_attribute.h"

/**
 * Object representing an IKEv2- TRANSFORM SUBSTRUCTURE
 * 
 * The TRANSFORM SUBSTRUCTURE format is described in RFC section 3.3.2.
 * 
 */
typedef struct transform_substructure_s transform_substructure_t;

struct transform_substructure_s {
	/**
	 * implements payload_t interface
	 */
	payload_t payload_interface;
	
	/**
	 * @brief Creates an iterator of stored transform_attribute_t objects.
	 * 
	 * @warning The created iterator has to get destroyed by the caller!
	 *
	 * @param this 			calling transform_substructure_t object
	 * @param iterator  		the created iterator is stored at the pointed pointer
	 * @param[in] forward 	iterator direction (TRUE: front to end)
	 * @return 		
	 * 						- SUCCESS or
	 * 						- OUT_OF_RES if iterator could not be created
	 */
	status_t (*create_transform_attribute_iterator) (transform_substructure_t *this,linked_list_iterator_t **iterator, bool forward);
	
	/**
	 * @brief Adds a transform_attribute_t object to this object.
	 * 
	 * @warning The added proposal_substructure_t object  is 
	 * 			getting destroyed in destroy function of transform_substructure_t.
	 *
	 * @param this 		calling transform_substructure_t object
	 * @param proposal  transform_attribute_t object to add
	 * @return 			- SUCCESS if succeeded
	 * 					- FAILED otherwise
	 */
	status_t (*add_transform_attribute) (transform_substructure_t *this,transform_attribute_t *attribute);
	
	/**
	 * @brief Destroys an transform_substructure_t object.
	 *
	 * @param this 	transform_substructure_t object to destroy
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*destroy) (transform_substructure_t *this);
};

/**
 * @brief Creates an empty transform_substructure_t object
 * 
 * @return			
 * 					- created transform_substructure_t object, or
 * 					- NULL if failed
 */
 
transform_substructure_t *transform_substructure_create();

#endif /*TRANSFORM_SUBSTRUCTURE_H_*/
