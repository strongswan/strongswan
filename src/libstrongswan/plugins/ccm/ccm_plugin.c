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

#include "ccm_plugin.h"

#include <library.h>

#include "ccm_aead.h"

static const char *plugin_name = "ccm";

typedef struct private_ccm_plugin_t private_ccm_plugin_t;

/**
 * private data of ccm_plugin
 */
struct private_ccm_plugin_t {

	/**
	 * public functions
	 */
	ccm_plugin_t public;
};

METHOD(plugin_t, destroy, void,
	private_ccm_plugin_t *this)
{
	lib->crypto->remove_aead(lib->crypto,
					(aead_constructor_t)ccm_aead_create);

	free(this);
}

/*
 * see header file
 */
plugin_t *ccm_plugin_create()
{
	private_ccm_plugin_t *this;

	INIT(this,
		.public.plugin.destroy = _destroy,
	);

	lib->crypto->add_aead(lib->crypto, ENCR_AES_CCM_ICV8, plugin_name,
					(aead_constructor_t)ccm_aead_create);
	lib->crypto->add_aead(lib->crypto, ENCR_AES_CCM_ICV12, plugin_name,
					(aead_constructor_t)ccm_aead_create);
	lib->crypto->add_aead(lib->crypto, ENCR_AES_CCM_ICV16, plugin_name,
					(aead_constructor_t)ccm_aead_create);
	lib->crypto->add_aead(lib->crypto, ENCR_CAMELLIA_CCM_ICV8, plugin_name,
					(aead_constructor_t)ccm_aead_create);
	lib->crypto->add_aead(lib->crypto, ENCR_CAMELLIA_CCM_ICV12, plugin_name,
					(aead_constructor_t)ccm_aead_create);
	lib->crypto->add_aead(lib->crypto, ENCR_CAMELLIA_CCM_ICV16, plugin_name,
					(aead_constructor_t)ccm_aead_create);

	return &this->public.plugin;
}
