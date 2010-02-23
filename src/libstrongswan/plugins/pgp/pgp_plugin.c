/*
 * Copyright (C) 2009 Martin Willi
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

#include "pgp_plugin.h"

#include <library.h>
#include "pgp_builder.h"
#include "pgp_encoder.h"
#include "pgp_cert.h"

typedef struct private_pgp_plugin_t private_pgp_plugin_t;

/**
 * private data of pgp_plugin
 */
struct private_pgp_plugin_t {

	/**
	 * public functions
	 */
	pgp_plugin_t public;
};

/**
 * Implementation of pgp_plugin_t.pgptroy
 */
static void destroy(private_pgp_plugin_t *this)
{
	lib->creds->remove_builder(lib->creds,
							(builder_function_t)pgp_public_key_load);
	lib->creds->remove_builder(lib->creds,
							(builder_function_t)pgp_private_key_load);

	lib->creds->remove_builder(lib->creds,
							(builder_function_t)pgp_cert_load);

	lib->encoding->remove_encoder(lib->encoding, pgp_encoder_encode);

	free(this);
}

/*
 * see header file
 */
plugin_t *pgp_plugin_create()
{
	private_pgp_plugin_t *this = malloc_thing(private_pgp_plugin_t);

	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;

	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
							(builder_function_t)pgp_public_key_load);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
							(builder_function_t)pgp_public_key_load);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_ANY,
							(builder_function_t)pgp_private_key_load);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
							(builder_function_t)pgp_private_key_load);

	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_GPG,
							(builder_function_t)pgp_cert_load);

	lib->encoding->add_encoder(lib->encoding, pgp_encoder_encode);

	return &this->public.plugin;
}

