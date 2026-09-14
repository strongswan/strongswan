/*
 * Copyright (C) 2026 Tobias Brunner
 *
 * Copyright (C) secunet Security Networks AG
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

#include "pem_bundle.h"

#include <collections/array.h>

typedef struct private_pem_bundle_t private_pem_bundle_t;

/**
 * Private data of a pem_t object.
 */
struct private_pem_bundle_t {

	/**
	 * Public interface.
	 */
	pem_bundle_t public;

	/**
	 * Contained certificates.
	 */
	array_t *certs;
};

METHOD(container_t, get_type, container_type_t,
	private_pem_bundle_t *this)
{
	return CONTAINER_PEM;
}

METHOD(container_t, create_signature_enumerator, enumerator_t*,
	private_pem_bundle_t *this)
{
	return enumerator_create_empty();
}

METHOD(container_t, get_data, bool,
	private_pem_bundle_t *this, chunk_t *data)
{
	return FALSE;
}

METHOD(container_t, get_encoding, bool,
	private_pem_bundle_t *this, chunk_t *data)
{
	/* we currently don't have any use for this */
	return FALSE;
}

METHOD(pem_t, create_cert_enumerator, enumerator_t*,
	private_pem_bundle_t *this)
{
	return array_create_enumerator(this->certs);
}

METHOD(pem_bundle_t, add_cert, void,
	private_pem_bundle_t *this, certificate_t *cert)
{
	array_insert_create(&this->certs, ARRAY_TAIL, cert);
}

METHOD(container_t, destroy, void,
	private_pem_bundle_t *this)
{
	array_destroy_offset(this->certs, offsetof(certificate_t, destroy));
	free(this);
}

/*
 * Described in header
 */
pem_bundle_t *pem_bundle_create()
{
	private_pem_bundle_t *this;

	INIT(this,
		.public = {
			.pem = {
				.container = {
					.get_type = _get_type,
					.create_signature_enumerator = _create_signature_enumerator,
					.get_data = _get_data,
					.get_encoding = _get_encoding,
					.destroy = _destroy,
				},
				.create_cert_enumerator = _create_cert_enumerator,
			},
			.add_cert = _add_cert,
		},
	);

	return &this->public;
}
