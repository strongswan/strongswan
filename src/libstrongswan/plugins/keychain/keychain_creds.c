/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

#include "keychain_creds.h"

#include <utils/debug.h>

typedef struct private_keychain_creds_t private_keychain_creds_t;

/**
 * Private data of an keychain_creds_t object.
 */
struct private_keychain_creds_t {

	/**
	 * Public keychain_creds_t interface.
	 */
	keychain_creds_t public;
};

METHOD(credential_set_t, create_cert_enumerator, enumerator_t*,
	private_keychain_creds_t *this, certificate_type_t cert, key_type_t key,
	identification_t *id, bool trusted)
{
	return enumerator_create_empty();
}

METHOD(keychain_creds_t, destroy, void,
	private_keychain_creds_t *this)
{
	free(this);
}

/**
 * See header
 */
keychain_creds_t *keychain_creds_create()
{
	private_keychain_creds_t *this;

	INIT(this,
		.public = {
			.set = {
				.create_shared_enumerator = (void*)enumerator_create_empty,
				.create_private_enumerator = (void*)enumerator_create_empty,
				.create_cert_enumerator = _create_cert_enumerator,
				.create_cdp_enumerator  = (void*)enumerator_create_empty,
				.cache_cert = (void*)nop,
			},
			.destroy = _destroy,
		},
	);

	return &this->public;
}
