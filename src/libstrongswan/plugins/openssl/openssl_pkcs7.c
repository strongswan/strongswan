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

#include "openssl_pkcs7.h"

#include <library.h>

typedef struct private_openssl_pkcs7_t private_openssl_pkcs7_t;

/**
 * Private data of an openssl_pkcs7_t object.
 */
struct private_openssl_pkcs7_t {

	/**
	 * Public pkcs7_t interface.
	 */
	pkcs7_t public;
};

METHOD(container_t, get_type, container_type_t,
	private_openssl_pkcs7_t *this)
{
	return CONTAINER_PKCS7_DATA;
}

METHOD(container_t, create_signature_enumerator, enumerator_t*,
	private_openssl_pkcs7_t *this)
{
	return enumerator_create_empty();
}

METHOD(pkcs7_t, get_attribute, bool,
	private_openssl_pkcs7_t *this, int oid,
	enumerator_t *enumerator, chunk_t *value)
{
	return FALSE;
}

METHOD(pkcs7_t, create_cert_enumerator, enumerator_t*,
	private_openssl_pkcs7_t *this)
{
	return enumerator_create_empty();
}

METHOD(container_t, get_data, bool,
	private_openssl_pkcs7_t *this, chunk_t *data)
{
	return FALSE;
}

METHOD(container_t, get_encoding, bool,
	private_openssl_pkcs7_t *this, chunk_t *data)
{
	return FALSE;
}

METHOD(container_t, destroy, void,
	private_openssl_pkcs7_t *this)
{
	free(this);
}

/**
 * Generic constructor
 */
static private_openssl_pkcs7_t* create_empty()
{
	private_openssl_pkcs7_t *this;

	INIT(this,
		.public = {
			.container = {
				.get_type = _get_type,
				.create_signature_enumerator = _create_signature_enumerator,
				.get_data = _get_data,
				.get_encoding = _get_encoding,
				.destroy = _destroy,
			},
			.get_attribute = _get_attribute,
			.create_cert_enumerator = _create_cert_enumerator,
		},
	);

	return this;
}

/**
 * See header
 */
pkcs7_t *openssl_pkcs7_load(container_type_t type, va_list args)
{
	chunk_t blob = chunk_empty;
	private_openssl_pkcs7_t *this;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	if (blob.len)
	{
		this = create_empty();
		/* TODO: parse blob */
		destroy(this);
	}
	return NULL;
}
