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
 * @defgroup transform_attribute transform_attribute
 * @{ @ingroup payloads
 */

#ifndef TRANSFORM_ATTRIBUTE_H_
#define TRANSFORM_ATTRIBUTE_H_

typedef enum transform_attribute_type_t transform_attribute_type_t;
typedef struct transform_attribute_t transform_attribute_t;

#include <library.h>
#include <encoding/payloads/payload.h>


/**
 * Type of the attribute, as in IKEv2 RFC 3.3.5.
 */
enum transform_attribute_type_t {
	ATTRIBUTE_UNDEFINED = 16384,
	KEY_LENGTH = 14
};

/** 
 * enum name for transform_attribute_type_t.
 */
extern enum_name_t *transform_attribute_type_names;

/**
 * Class representing an IKEv2- TRANSFORM Attribute.
 * 
 * The TRANSFORM ATTRIBUTE format is described in RFC section 3.3.5.
 */
struct transform_attribute_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Returns the currently set value of the attribute.
	 * 	
	 * Returned data are not copied.
	 * 
	 * @return 		chunk_t pointing to the value
	 */
	chunk_t (*get_value_chunk) (transform_attribute_t *this);
	
	/**
	 * Returns the currently set value of the attribute.
	 * 	
	 * Returned data are not copied.
	 * 
	 * @return 		value
	 */
	u_int16_t (*get_value) (transform_attribute_t *this);
	
	/**
	 * Sets the value of the attribute.
	 * 	
	 * Value is getting copied.
	 * 
	 * @param value chunk_t pointing to the value to set
	 */
	void (*set_value_chunk) (transform_attribute_t *this, chunk_t value);

	/**
	 * Sets the value of the attribute.
	 * 
	 * @param value value to set
	 */
	void (*set_value) (transform_attribute_t *this, u_int16_t value);

	/**
	 * Sets the type of the attribute.
	 * 	
	 * @param type	type to set (most significant bit is set to zero)
	 */
	void (*set_attribute_type) (transform_attribute_t *this, u_int16_t type);
	
	/**
	 * get the type of the attribute.
	 * 	
	 * @return 		type of the value
	 */
	u_int16_t (*get_attribute_type) (transform_attribute_t *this);
	
	/**
	 * Clones an transform_attribute_t object.
	 *
	 * @return		cloned transform_attribute_t object
	 */
	transform_attribute_t * (*clone) (transform_attribute_t *this);

	/**
	 * Destroys an transform_attribute_t object.
	 */
	void (*destroy) (transform_attribute_t *this);
};

/**
 * Creates an empty transform_attribute_t object.
 * 
 * @return				transform_attribute_t object
 */
transform_attribute_t *transform_attribute_create(void);

/**
 * Creates an transform_attribute_t of type KEY_LENGTH.
 * 
 * @param key_length	key length in bytes
 * @return				transform_attribute_t object
 */
transform_attribute_t *transform_attribute_create_key_length(u_int16_t key_length);

#endif /*TRANSFORM_ATTRIBUTE_H_ @} */
