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

#include "af_alg_plugin.h"

#include <library.h>

#include "af_alg_hasher.h"
#include "af_alg_signer.h"
#include "af_alg_prf.h"
#include "af_alg_crypter.h"

typedef struct private_af_alg_plugin_t private_af_alg_plugin_t;

/**
 * private data of af_alg_plugin
 */
struct private_af_alg_plugin_t {

	/**
	 * public functions
	 */
	af_alg_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_af_alg_plugin_t *this)
{
	return "af-alg";
}

METHOD(plugin_t, destroy, void,
	private_af_alg_plugin_t *this)
{
	lib->crypto->remove_hasher(lib->crypto,
					(hasher_constructor_t)af_alg_hasher_create);
	lib->crypto->remove_signer(lib->crypto,
					(signer_constructor_t)af_alg_signer_create);
	lib->crypto->remove_prf(lib->crypto,
					(prf_constructor_t)af_alg_prf_create);
	lib->crypto->remove_crypter(lib->crypto,
					(crypter_constructor_t)af_alg_crypter_create);

	free(this);
}

/*
 * see header file
 */
plugin_t *af_alg_plugin_create()
{
	private_af_alg_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
	);

	af_alg_hasher_probe(get_name(this));
	af_alg_signer_probe(get_name(this));
	af_alg_prf_probe(get_name(this));
	af_alg_crypter_probe(get_name(this));

	return &this->public.plugin;
}
