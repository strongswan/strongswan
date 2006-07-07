/**
 * @file transform_attribute.h
 * 
 * @brief Interface of transform_attribute_t.
 * 
 */

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

#ifndef TRANSFORM_ATTRIBUTE_H_
#define TRANSFORM_ATTRIBUTE_H_

#include <types.h>
#include <encoding/payloads/payload.h>


typedef enum transform_attribute_type_t transform_attribute_type_t;

/**
 * Type of the attribute, as in IKEv2 RFC 3.3.5.
 * 
 * @ingroup payloads
 */
enum transform_attribute_type_t {
	ATTRIBUTE_UNDEFINED = 16384,
	KEY_LENGTH = 14
};

/** 
 * String mappings for transform_attribute_type_t.
 * 
 * @ingroup payloads
 */
extern mapping_t transform_attribute_type_m[];

typedef struct transform_attribute_t transform_attribute_t;

/**
 * @brief Class representing an IKEv2- TRANSFORM Attribute.
 * 
 * The TRANSFORM ATTRIBUTE format is described in RFC section 3.3.5.
 * 
 * @ingroup payloads
 */
struct transform_attribute_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * @brief Returns the currently set value of the attribute.
	 * 	
	 * @warning Returned data are not copied.
	 * 
	 * @param this 	calling transform_attribute_t object
	 * @return 		chunk_t pointing to the value
	 */
	chunk_t (*get_value_chunk) (transform_attribute_t *this);
	
	/**
	 * @brief Returns the currently set value of the attribute.
	 * 	
	 * @warning Returned data are not copied.
	 * 
	 * @param this 	calling transform_attribute_t object
	 * @return 		value
	 */
	u_int16_t (*get_value) (transform_attribute_t *this);
	
	/**
	 * @brief Sets the value of the attribute.
	 * 	
	 * @warning Value is getting copied.
	 * 
	 * @param this 	calling transform_attribute_t object
	 * @param value chunk_t pointing to the value to set
	 */
	void (*set_value_chunk) (transform_attribute_t *this, chunk_t value);

	/**
	 * @brief Sets the value of the attribute.
	 * 
	 * @param this 	calling transform_attribute_t object
	 * @param value value to set
	 */
	void (*set_value) (transform_attribute_t *this, u_int16_t value);

	/**
	 * @brief Sets the type of the attribute.
	 * 	
	 * @param this 	calling transform_attribute_t object
	 * @param type	type to set (most significant bit is set to zero)
	 */
	void (*set_attribute_type) (transform_attribute_t *this, u_int16_t type);
	
	/**
	 * @brief get the type of the attribute.
	 * 	
	 * @param this 	calling transform_attribute_t object
	 * @return 		type of the value
	 */
	u_int16_t (*get_attribute_type) (transform_attribute_t *this);
	
	/**
	 * @brief Clones an transform_attribute_t object.
	 *
	 * @param this 	transform_attribute_t object to clone
	 * @return		cloned transform_attribute_t object
	 */
	transform_attribute_t * (*clone) (transform_attribute_t *this);

	/**
	 * @brief Destroys an transform_attribute_t object.
	 *
	 * @param this 	transform_attribute_t object to destroy
	 */
	void (*destroy) (transform_attribute_t *this);
};

/**
 * @brief Creates an empty transform_attribute_t object.
 * 
 * @return				transform_attribute_t object
 * 
 * @ingroup payloads
 */
transform_attribute_t *transform_attribute_create(void);

/**
 * @brief Creates an transform_attribute_t of type KEY_LENGTH.
 * 
 * @param key_length	key length in bytes
 * @return				transform_attribute_t object
 * 
 * @ingroup payloads
 */
transform_attribute_t *transform_attribute_create_key_length(u_int16_t key_length);


#endif /*TRANSFORM_ATTRIBUTE_H_*/
