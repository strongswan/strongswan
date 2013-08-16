/*
 * Copyright (C) 2013 Andreas Steffen
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

#include "swid_tag.h"

typedef struct private_swid_tag_t private_swid_tag_t;

/**
 * Private data of a swid_tag_t object.
 *
 */
struct private_swid_tag_t {

	/**
	 * Public swid_tag_t interface.
	 */
	swid_tag_t public;

	/**
	 * UTF-8 XML encoding of SWID tag
	 */
	chunk_t encoding;

	/**
	 * Optional Unique Sequence ID
	 */
	chunk_t unique_seq_id;

};

METHOD(swid_tag_t, get_encoding, chunk_t,
	private_swid_tag_t *this)
{
	return this->encoding;
}

METHOD(swid_tag_t, get_unique_seq_id, chunk_t,
	private_swid_tag_t *this)
{
	return this->unique_seq_id;
}

METHOD(swid_tag_t, destroy, void,
	private_swid_tag_t *this)
{
	free(this->encoding.ptr);
	free(this->unique_seq_id.ptr);
	free(this);
}

/**
 * See header
 */
swid_tag_t *swid_tag_create(chunk_t encoding, chunk_t unique_seq_id)
{
	private_swid_tag_t *this;

	INIT(this,
		.public = {
			.get_encoding = _get_encoding,
			.get_unique_seq_id = _get_unique_seq_id,
			.destroy = _destroy,
		},
		.encoding = chunk_clone(encoding),
	);

	if (unique_seq_id.len > 0)
	{
		this->unique_seq_id = chunk_clone(unique_seq_id);
	}

	return &this->public;
}

