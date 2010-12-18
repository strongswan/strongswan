/*
 * Copyright (C) 2008 Martin Willi
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

#include "hmac_plugin.h"

#include <library.h>
#include "hmac_signer.h"
#include "hmac_prf.h"

static const char *plugin_name = "hmac";

typedef struct private_hmac_plugin_t private_hmac_plugin_t;

/**
 * private data of hmac_plugin
 */
struct private_hmac_plugin_t {

	/**
	 * public functions
	 */
	hmac_plugin_t public;
};

METHOD(plugin_t, destroy, void,
	private_hmac_plugin_t *this)
{
	lib->crypto->remove_prf(lib->crypto,
							(prf_constructor_t)hmac_prf_create);
	lib->crypto->remove_signer(lib->crypto,
							   (signer_constructor_t)hmac_signer_create);
	free(this);
}

/*
 * see header file
 */
plugin_t *hmac_plugin_create()
{
	private_hmac_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.destroy = _destroy,
			},
		},
	);

	lib->crypto->add_prf(lib->crypto, PRF_HMAC_SHA2_256, plugin_name,
						 (prf_constructor_t)hmac_prf_create);
	lib->crypto->add_prf(lib->crypto, PRF_HMAC_SHA1, plugin_name,
						 (prf_constructor_t)hmac_prf_create);
	lib->crypto->add_prf(lib->crypto, PRF_HMAC_MD5, plugin_name,
						 (prf_constructor_t)hmac_prf_create);
	lib->crypto->add_prf(lib->crypto, PRF_HMAC_SHA2_384, plugin_name,
						 (prf_constructor_t)hmac_prf_create);
	lib->crypto->add_prf(lib->crypto, PRF_HMAC_SHA2_512, plugin_name,
						 (prf_constructor_t)hmac_prf_create);

	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA1_96, plugin_name,
							(signer_constructor_t)hmac_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA1_128, plugin_name,
							(signer_constructor_t)hmac_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA1_160, plugin_name,
							(signer_constructor_t)hmac_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA2_256_128, plugin_name,
							(signer_constructor_t)hmac_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA2_256_256, plugin_name,
							(signer_constructor_t)hmac_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_MD5_96, plugin_name,
							(signer_constructor_t)hmac_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_MD5_128, plugin_name,
							(signer_constructor_t)hmac_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA2_384_192, plugin_name,
							(signer_constructor_t)hmac_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA2_384_384, plugin_name,
							(signer_constructor_t)hmac_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA2_512_256, plugin_name,
							(signer_constructor_t)hmac_signer_create);

	return &this->public.plugin;
}

