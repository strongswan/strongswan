/*
 * Copyright (C) 2013-2014 Andreas Steffen
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
 * @defgroup swid_tag swid_tag
 * @{ @ingroup swid
 */

#ifndef SWID_TAG_H_
#define SWID_TAG_H_

#include <library.h>

typedef struct swid_tag_t swid_tag_t;


/**
 * Class storing a SWID Tag
 */
struct swid_tag_t {

	/**
	 * Get UTF-8 XML encoding of SWID tag
	 *
	 * @return				XML encoding of SWID tag
	 */
	chunk_t (*get_encoding)(swid_tag_t *this);

	/**
	 * Get th Optional Tag File Path
	 *
	 * @return				Optional Tag File Path
	 */
	chunk_t (*get_tag_file_path)(swid_tag_t *this);

	/**
	 * Get a new reference to the swid_tag object
	 *
	 * @return			this, with an increased refcount
	 */
	swid_tag_t* (*get_ref)(swid_tag_t *this);

	/**
	 * Destroys a swid_tag_t object.
	 */
	void (*destroy)(swid_tag_t *this);

};

/**
 * Creates a swid_tag_t object
 *
 * @param encoding			XML encoding of SWID tag
 * @param tag_file_path		Tag File Path or empty chunk
 */
swid_tag_t* swid_tag_create(chunk_t encoding, chunk_t tag_file_path);

#endif /** SWID_TAG_H_ @}*/
