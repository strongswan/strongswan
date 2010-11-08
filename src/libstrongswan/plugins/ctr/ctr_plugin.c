/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "ctr_plugin.h"

#include <library.h>

#include "ctr_ipsec_crypter.h"

static const char *plugin_name = "ctr";

typedef struct private_ctr_plugin_t private_ctr_plugin_t;

/**
 * private data of ctr_plugin
 */
struct private_ctr_plugin_t {

	/**
	 * public functions
	 */
	ctr_plugin_t public;
};

METHOD(plugin_t, destroy, void,
	private_ctr_plugin_t *this)
{
	lib->crypto->remove_crypter(lib->crypto,
					(crypter_constructor_t)ctr_ipsec_crypter_create);

	free(this);
}

/*
 * see header file
 */
plugin_t *ctr_plugin_create()
{
	private_ctr_plugin_t *this;
	crypter_t *crypter;

	INIT(this,
		.public = {
			.plugin = {
				.destroy = _destroy,
			},
		},
	);

	crypter = lib->crypto->create_crypter(lib->crypto, ENCR_AES_CBC, 16);
	if (crypter)
	{
		crypter->destroy(crypter);
		lib->crypto->add_crypter(lib->crypto, ENCR_AES_CTR, plugin_name,
						(crypter_constructor_t)ctr_ipsec_crypter_create);
	}
	crypter = lib->crypto->create_crypter(lib->crypto, ENCR_CAMELLIA_CBC, 16);
	if (crypter)
	{
		crypter->destroy(crypter);
		lib->crypto->add_crypter(lib->crypto, ENCR_CAMELLIA_CTR, plugin_name,
						(crypter_constructor_t)ctr_ipsec_crypter_create);
	}
	return &this->public.plugin;
}
