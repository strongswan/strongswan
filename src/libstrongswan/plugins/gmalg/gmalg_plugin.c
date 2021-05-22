/*
 * Copyright (C) 2008-2016 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
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

#include <library.h>
#include <utils/debug.h>
#include <threading/thread.h>
#include <threading/mutex.h>
#include <threading/thread_value.h>

#include <gmalg.h>

#include "gmalg_plugin.h"
#include "gmalg_crypter.h"
#include "gmalg_hasher.h"
#include "gmalg_ec_private_key.h"
#include "gmalg_ec_public_key.h"
#include "gmalg_rng.h"
#include "gmalg_ec_diffie_hellman.h"

typedef struct private_gmalg_plugin_t private_gmalg_plugin_t;

/**
 * private data of gmalg_plugin
 */
struct private_gmalg_plugin_t {

	/**
	 * public functions
	 */
	gmalg_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_gmalg_plugin_t *this)
{
	return "gmalg";
}

METHOD(plugin_t, get_features, int,
	private_gmalg_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		/* we provide GmSdf threading callbacks */
		PLUGIN_PROVIDE(CUSTOM, "gmalg-threading"),
		/* crypters */
		PLUGIN_REGISTER(CRYPTER, gmalg_crypter_create),
			PLUGIN_PROVIDE(CRYPTER, ENCR_SM1_ECB, 16),
			PLUGIN_PROVIDE(CRYPTER, ENCR_SM1_CBC, 16),
			PLUGIN_PROVIDE(CRYPTER, ENCR_SM4_ECB, 16),
			PLUGIN_PROVIDE(CRYPTER, ENCR_SM4_CBC, 16),
			PLUGIN_PROVIDE(CRYPTER, ENCR_NULL, 0),
		/* hashers */
		PLUGIN_REGISTER(HASHER, gmalg_hasher_create),
			PLUGIN_PROVIDE(HASHER, HASH_SM3),
		/* EC DH groups */
		PLUGIN_REGISTER(DH, gmalg_ec_diffie_hellman_create),
					PLUGIN_PROVIDE(DH, CURVE_SM2),
		/* EC private/public key loading */
		PLUGIN_REGISTER(PRIVKEY, gmalg_ec_private_key_load, TRUE),
			PLUGIN_PROVIDE(PRIVKEY, KEY_SM2),
		PLUGIN_REGISTER(PRIVKEY_GEN, gmalg_ec_private_key_gen, FALSE),
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_SM2),
		PLUGIN_REGISTER(PUBKEY, gmalg_ec_public_key_load, TRUE),
			PLUGIN_PROVIDE(PUBKEY, KEY_SM2),
		/* signature encryption schemes */
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_SM2_WITH_SM3),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_SM2_WITH_SM3),

		PLUGIN_REGISTER(RNG, gmalg_rng_create),
			PLUGIN_PROVIDE(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(RNG, RNG_WEAK),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_gmalg_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *gmalg_plugin_create()
{
	private_gmalg_plugin_t *this;

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
