/*
 * Copyright (C) 2015 Martin Willi
 * Copyright (C) 2015 revosec AG
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

#include "cga_plugin.h"
#include "cga_cert.h"
#include "cga_trust.h"

#include <library.h>

typedef struct private_cga_plugin_t private_cga_plugin_t;

/**
 * Private data of cga_plugin_t
 */
struct private_cga_plugin_t {

	/**
	 * Public functions
	 */
	cga_plugin_t public;

	/**
	 * Credential set providing a virtual CGA trust anchor
	 */
	cga_trust_t *trust;
};

METHOD(plugin_t, get_name, char*,
	private_cga_plugin_t *this)
{
	return "cga";
}

METHOD(plugin_t, get_features, int,
	private_cga_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(CERT_ENCODE, cga_cert_gen, FALSE),
			PLUGIN_PROVIDE(CERT_ENCODE, CERT_CGA_PARAMS),
				PLUGIN_DEPENDS(HASHER, HASH_SHA1),
				PLUGIN_DEPENDS(RNG, RNG_WEAK),
		PLUGIN_REGISTER(CERT_DECODE, cga_cert_load, TRUE),
			PLUGIN_PROVIDE(CERT_DECODE, CERT_CGA_PARAMS),
				PLUGIN_DEPENDS(HASHER, HASH_SHA1),
				PLUGIN_DEPENDS(PUBKEY, KEY_ANY),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, reload, bool,
	private_cga_plugin_t *this)
{
	lib->credmgr->remove_set(lib->credmgr, &this->trust->set);
	lib->credmgr->flush_cache(lib->credmgr, CERT_CGA_PARAMS);
	if (lib->settings->get_bool(lib->settings,
								"%s.plugins.cga.trust", FALSE, lib->ns))
	{
		lib->credmgr->add_set(lib->credmgr, &this->trust->set);
	}
	return TRUE;
}

METHOD(plugin_t, destroy, void,
	private_cga_plugin_t *this)
{
	lib->credmgr->remove_set(lib->credmgr, &this->trust->set);
	this->trust->destroy(this->trust);
	free(this);
}

/*
 * see header file
 */
plugin_t *cga_plugin_create()
{
	private_cga_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.reload = _reload,
				.destroy = _destroy,
			},
		},
		.trust = cga_trust_create(),
	);

	reload(this);

	return &this->public.plugin;
}
