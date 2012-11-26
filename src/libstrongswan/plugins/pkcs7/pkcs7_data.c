/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "pkcs7_data.h"

#include <asn1/asn1.h>

typedef struct private_pkcs7_data_t private_pkcs7_data_t;

/**
 * Private data of a PKCS#7 signed-data container.
 */
struct private_pkcs7_data_t {

	/**
	 * Implements pkcs7_t.
	 */
	pkcs7_t public;

	/**
	 * Encoded data
	 */
	chunk_t content;

	/**
	 * Encoded PKCS#7 signed-data
	 */
	chunk_t encoding;
};

METHOD(container_t, get_type, container_type_t,
	private_pkcs7_data_t *this)
{
	return CONTAINER_PKCS7_DATA;
}

METHOD(container_t, create_signature_enumerator, enumerator_t*,
	private_pkcs7_data_t *this)
{
	return enumerator_create_empty();
}

METHOD(container_t, get_data, bool,
	private_pkcs7_data_t *this, chunk_t *data)
{
	chunk_t chunk;

	chunk = this->content;
	if (asn1_unwrap(&chunk, &chunk) == ASN1_OCTET_STRING)
	{
		*data = chunk_clone(chunk);
		return TRUE;
	}
	return FALSE;
}

METHOD(container_t, get_encoding, bool,
	private_pkcs7_data_t *this, chunk_t *data)
{
	*data = chunk_clone(this->encoding);
	return TRUE;
}

METHOD(container_t, destroy, void,
	private_pkcs7_data_t *this)
{
	free(this->content.ptr);
	free(this->encoding.ptr);
	free(this);
}

/**
 * See header.
 */
pkcs7_t *pkcs7_data_load(chunk_t encoding, chunk_t content)
{
	private_pkcs7_data_t *this;

	INIT(this,
		.public = {
			.container = {
				.get_type = _get_type,
				.create_signature_enumerator = _create_signature_enumerator,
				.get_data = _get_data,
				.get_encoding = _get_encoding,
				.destroy = _destroy,
			},
		},
		.encoding = chunk_clone(encoding),
		.content = chunk_clone(content),
	);

	return &this->public;
}
