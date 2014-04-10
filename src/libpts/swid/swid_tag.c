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
	 * Optional Tag File Path
	 */
	chunk_t tag_file_path;

	/**
	 * Reference count
	 */
	refcount_t ref;
};

METHOD(swid_tag_t, get_encoding, chunk_t,
	private_swid_tag_t *this)
{
	return this->encoding;
}

METHOD(swid_tag_t, get_tag_file_path, chunk_t,
	private_swid_tag_t *this)
{
	return this->tag_file_path;
}

METHOD(swid_tag_t, get_ref, swid_tag_t*,
	private_swid_tag_t *this)
{
	ref_get(&this->ref);
	return &this->public;
}

METHOD(swid_tag_t, destroy, void,
	private_swid_tag_t *this)
{
	if (ref_put(&this->ref))
	{
		free(this->encoding.ptr);
		free(this->tag_file_path.ptr);
		free(this);
	}
}

/**
 * See header
 */
swid_tag_t *swid_tag_create(chunk_t encoding, chunk_t tag_file_path)
{
	private_swid_tag_t *this;

	INIT(this,
		.public = {
			.get_encoding = _get_encoding,
			.get_tag_file_path = _get_tag_file_path,
			.get_ref = _get_ref,
			.destroy = _destroy,
		},
		.encoding = chunk_clone(encoding),
		.ref = 1,
	);

	if (tag_file_path.len > 0)
	{
		this->tag_file_path = chunk_clone(tag_file_path);
	}

	return &this->public;
}

