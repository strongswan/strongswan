/**
 * @file transform_attribute.h
 * 
 * @brief Declaration of the class transform_attribute_t. 
 * 
 * An object of this type represents an IKEv2 TRANSFORM attribute.
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

#ifndef TRANSFORM_ATTRIBUTE_H_
#define TRANSFORM_ATTRIBUTE_H_

#include "../types.h"
#include "payload.h"

/**
 * Object representing an IKEv2- TRANSFORM Attribute
 * 
 * The TRANSFORM ATTRIBUTE format is described in RFC section 3.3.5.
 * 
 */
typedef struct transform_attribute_s transform_attribute_t;

struct transform_attribute_s {
	/**
	 * implements payload_t interface
	 */
	payload_t payload_interface;

	/**
	 * @brief Returns the currently set value of the attribute
	 * 	
	 * @warning Returned data are not copied
	 * 
	 * @param this 	calling transform_attribute_t object
	 * @return 		chunk_t pointing to the value
	 */
	chunk_t (*get_value) (transform_attribute_t *this);
	
	/**
	 * @brief Sets the value of the attribute.
	 * 	
	 * @warning Value is getting copied
	 * 
	 * @param this 	calling transform_attribute_t object
	 * @param value chunk_t pointing to the value to set
	 * @return 		
	 * 				- SUCCESS or
	 * 				- OUT_OF_RES
	 */
	status_t (*set_value) (transform_attribute_t *this, chunk_t value);

	/**
	 * @brief Sets the type of the attribute.
	 * 	
	 * @param this 	calling transform_attribute_t object
	 * @param type	type to set (most significant bit is set to zero)
	 * @return 		SUCCESS
	 */
	status_t (*set_attribute_type) (transform_attribute_t *this, u_int16_t type);
	
	/**
	 * @brief get the type of the attribute.
	 * 	
	 * @param this 	calling transform_attribute_t object
	 * @return 		type of the value
	 */
	u_int16_t (*get_attribute_type) (transform_attribute_t *this);
	
	/**
	 * @brief Destroys an transform_attribute_t object.
	 *
	 * @param this 	transform_attribute_t object to destroy
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*destroy) (transform_attribute_t *this);
};

/**
 * @brief Creates an empty transform_attribute_t object
 * 
 * @return			
 * 					- created transform_attribute_t object, or
 * 					- NULL if failed
 */
 
transform_attribute_t *transform_attribute_create();

#endif /*TRANSFORM_ATTRIBUTE_H_*/
