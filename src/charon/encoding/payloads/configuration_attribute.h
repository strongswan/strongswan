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
 * @defgroup configuration_attribute configuration_attribute
 * @{ @ingroup payloads
 */

#ifndef CONFIGURATION_ATTRIBUTE_H_
#define CONFIGURATION_ATTRIBUTE_H_

typedef struct configuration_attribute_t configuration_attribute_t;

#include <library.h>
#include <attributes/attributes.h>
#include <encoding/payloads/payload.h>


/**
 * Configuration attribute header length in bytes.
 */
#define CONFIGURATION_ATTRIBUTE_HEADER_LENGTH 4

/**
 * Class representing an IKEv2-CONFIGURATION Attribute.
 *
 * The CONFIGURATION ATTRIBUTE format is described in RFC section 3.15.1.
 */
struct configuration_attribute_t {
	/**
	 * The payload_t interface.
	 */
	payload_t payload_interface;

	/**
	 * Returns the currently set value of the attribute.
	 *
	 * @warning Returned data are not copied.
	 *
	 * @return 		chunk_t pointing to the value
	 */
	chunk_t (*get_value) (configuration_attribute_t *this);

	/**
	 * Sets the value of the attribute.
	 *
	 * Value is getting copied.
	 *
	 * @param value chunk_t pointing to the value to set
	 */
	void (*set_value) (configuration_attribute_t *this, chunk_t value);

	/**
	 * Sets the type of the attribute.
	 *
	 * @param type	type to set (most significant bit is set to zero)
	 */
	void (*set_type) (configuration_attribute_t *this, u_int16_t type);

	/**
	 * get the type of the attribute.
	 *
	 * @return 		type of the value
	 */
	u_int16_t (*get_type) (configuration_attribute_t *this);

	/**
	 * get the length of an attribute.
	 *
	 * @return 		type of the value
	 */
	u_int16_t (*get_length) (configuration_attribute_t *this);

	/**
	 * Destroys an configuration_attribute_t object.
	 */
	void (*destroy) (configuration_attribute_t *this);
};

/**
 * Creates an empty configuration_attribute_t object.
 *
 * @return			created configuration_attribute_t object
 */
configuration_attribute_t *configuration_attribute_create(void);

#endif /** CONFIGURATION_ATTRIBUTE_H_ @}*/
