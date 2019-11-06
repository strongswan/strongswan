/*
 * Copyright (C) 2019 Andreas Steffen
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

#include "frodo_plugin.h"
#include "frodo.h"

#include <library.h>

typedef struct private_frodo_plugin_t private_frodo_plugin_t;

/**
 * private data of frodo_plugin
 */
struct private_frodo_plugin_t {

	/**
	 * public functions
	 */
	frodo_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_frodo_plugin_t *this)
{
	return "frodo";
}

METHOD(plugin_t, get_features, int,
	private_frodo_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(KE, frodo_create),
			PLUGIN_PROVIDE(KE, KE_FRODO_SHAKE_L1),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_128),
				PLUGIN_DEPENDS(DRBG, DRBG_CTR_AES256),
				PLUGIN_DEPENDS(RNG, RNG_TRUE),
			PLUGIN_PROVIDE(KE, KE_FRODO_SHAKE_L3),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_256),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_128),
				PLUGIN_DEPENDS(DRBG, DRBG_CTR_AES256),
				PLUGIN_DEPENDS(RNG, RNG_TRUE),
			PLUGIN_PROVIDE(KE, KE_FRODO_SHAKE_L5),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_256),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_128),
				PLUGIN_DEPENDS(DRBG, DRBG_CTR_AES256),
				PLUGIN_DEPENDS(RNG, RNG_TRUE),
			PLUGIN_PROVIDE(KE, KE_FRODO_AES_L1),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_128),
				PLUGIN_DEPENDS(CRYPTER, ENCR_AES_ECB, 16),
				PLUGIN_DEPENDS(DRBG, DRBG_CTR_AES256),
				PLUGIN_DEPENDS(RNG, RNG_TRUE),
			PLUGIN_PROVIDE(KE, KE_FRODO_AES_L3),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_256),
				PLUGIN_DEPENDS(CRYPTER, ENCR_AES_ECB, 16),
				PLUGIN_DEPENDS(DRBG, DRBG_CTR_AES256),
				PLUGIN_DEPENDS(RNG, RNG_TRUE),
			PLUGIN_PROVIDE(KE, KE_FRODO_AES_L5),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_256),
				PLUGIN_DEPENDS(CRYPTER, ENCR_AES_ECB, 16),
				PLUGIN_DEPENDS(DRBG, DRBG_CTR_AES256),
				PLUGIN_DEPENDS(RNG, RNG_TRUE),
	};
	*features = f;

	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_frodo_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *frodo_plugin_create()
{
	private_frodo_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
