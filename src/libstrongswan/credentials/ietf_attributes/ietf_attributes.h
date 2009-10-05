/*
 * Copyright (C) 2007-2009 Andreas Steffen
 *
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup ietf_attributes ietf_attributes
 * @{ @ingroup credentials
 */

#ifndef IETF_ATTRIBUTES_H_
#define IETF_ATTRIBUTES_H_

typedef struct ietf_attributes_t ietf_attributes_t;

#include <library.h>

/**
 *
 */
struct ietf_attributes_t {

	/**
	 * Get the an alphabetically sorted list of printable IETF attributes.
	 *
	 * Result points to internal data, do not free.
	 *
	 * @return 			a string containing printable attributes
	 */
	char* (*get_string) (ietf_attributes_t *this);

	/**
	 * Get the ASN.1 encoding of the IETF attributes.
	 *
	 * @return 			allocated chunk containing the encoded bytes
	 */
	chunk_t (*get_encoding) (ietf_attributes_t *this);

	/**
	 * Check for equality between two lists.
	 *
	 * @param other		attribute list to be checked for equality
	 * @return 			TRUE if equal
	 */
	bool (*equals) (ietf_attributes_t *this, ietf_attributes_t *other);

	/**
	 * Check for common attributes between two lists.
	 *
	 * @param other		attribute list to be matched 
	 * @return 			TRUE if there is at least a common attribute
	 */
	bool (*matches) (ietf_attributes_t *this, ietf_attributes_t *other);

	/**
	 * Get a new reference to the IETF attributes.
	 *
	 * @return			this, with an increased refcount
	 */
	ietf_attributes_t* (*get_ref)(ietf_attributes_t *this);

	/**
	 * Destroys an ietf_attributes_t object.
	 */
	void (*destroy) (ietf_attributes_t *this);
};

/**
 * @param string	input string, which will be converted
 * @return			ietf_attributes_t
 */
ietf_attributes_t *ietf_attributes_create_from_string(char *string);

/**
 * @param encoded	ASN.1 encoded bytes, such as from ietf_attributes.get_encoding
 * @return			ietf_attributes_t
 */
ietf_attributes_t *ietf_attributes_create_from_encoding(chunk_t encoded);

#endif /** IETF_ATTRIBUTES_H_ @}*/

