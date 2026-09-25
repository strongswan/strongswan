/*
 * Copyright (C) 2024 Tobias Brunner
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

#include "ml_plugin.h"

#include <plugins/plugin.h>

#include "ml_kem.h"
#include "ml_dsa_public_key.h"
#include "ml_dsa_private_key.h"

typedef struct private_plugin_t private_plugin_t;

/**
 * Private data.
 */
struct private_plugin_t {

	/**
	 * Public interface.
	 */
	plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_plugin_t *this)
{
	return "ml";
}

/**
 * Helper macros to declare dependencies for ML-DSA.
 */
#define ML_DSA_DEPS \
	PLUGIN_DEPENDS(XOF, XOF_SHAKE_128), \
	PLUGIN_DEPENDS(XOF, XOF_SHAKE_256)

#define ML_DSA_PUBKEY_DEPS \
	ML_DSA_DEPS, \
	PLUGIN_DEPENDS(HASHER, HASH_SHA1)

#define ML_DSA_PRIVKEY_DEPS \
	ML_DSA_DEPS, \
	PLUGIN_DEPENDS(RNG, RNG_STRONG)

#define ML_DSA_PRIVKEY_GEN_DEPS \
	ML_DSA_PRIVKEY_DEPS, \
	PLUGIN_DEPENDS(RNG, RNG_TRUE)

METHOD(plugin_t, get_features, int,
	private_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(KE, ml_kem_create),
			PLUGIN_PROVIDE(KE, ML_KEM_512),
				PLUGIN_DEPENDS(HASHER, HASH_SHA3_256),
				PLUGIN_DEPENDS(HASHER, HASH_SHA3_512),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_128),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_256),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(KE, ML_KEM_768),
				PLUGIN_DEPENDS(HASHER, HASH_SHA3_256),
				PLUGIN_DEPENDS(HASHER, HASH_SHA3_512),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_128),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_256),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(KE, ML_KEM_1024),
				PLUGIN_DEPENDS(HASHER, HASH_SHA3_256),
				PLUGIN_DEPENDS(HASHER, HASH_SHA3_512),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_128),
				PLUGIN_DEPENDS(XOF, XOF_SHAKE_256),
				PLUGIN_DEPENDS(RNG, RNG_STRONG),
		PLUGIN_REGISTER(PUBKEY, ml_dsa_public_key_load, TRUE),
			PLUGIN_PROVIDE(PUBKEY, KEY_ML_DSA_44),
				ML_DSA_PUBKEY_DEPS,
			PLUGIN_PROVIDE(PUBKEY, KEY_ML_DSA_65),
				ML_DSA_PUBKEY_DEPS,
			PLUGIN_PROVIDE(PUBKEY, KEY_ML_DSA_87),
				ML_DSA_PUBKEY_DEPS,
			PLUGIN_PROVIDE(PUBKEY, KEY_ANY),
				ML_DSA_PUBKEY_DEPS,
		PLUGIN_REGISTER(PRIVKEY, ml_dsa_private_key_load, TRUE),
			PLUGIN_PROVIDE(PRIVKEY, KEY_ML_DSA_44),
				ML_DSA_PRIVKEY_DEPS,
			PLUGIN_PROVIDE(PRIVKEY, KEY_ML_DSA_65),
				ML_DSA_PRIVKEY_DEPS,
			PLUGIN_PROVIDE(PRIVKEY, KEY_ML_DSA_87),
				ML_DSA_PRIVKEY_DEPS,
		PLUGIN_REGISTER(PRIVKEY_GEN, ml_dsa_private_key_gen, FALSE),
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_ML_DSA_44),
				ML_DSA_PRIVKEY_GEN_DEPS,
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_ML_DSA_65),
				ML_DSA_PRIVKEY_GEN_DEPS,
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_ML_DSA_87),
				ML_DSA_PRIVKEY_GEN_DEPS,
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_ML_DSA_44),
			ML_DSA_PRIVKEY_DEPS,
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_ML_DSA_65),
			ML_DSA_PRIVKEY_DEPS,
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_ML_DSA_87),
			ML_DSA_PRIVKEY_DEPS,
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_ML_DSA_44),
			ML_DSA_PUBKEY_DEPS,
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_ML_DSA_65),
			ML_DSA_PUBKEY_DEPS,
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_ML_DSA_87),
			ML_DSA_PUBKEY_DEPS,
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_plugin_t *this)
{
	free(this);
}

/*
 * Described in header
 */
PLUGIN_DEFINE(ml)
{
	private_plugin_t *this;

	INIT(this,
		.public = {
			.get_name = _get_name,
			.get_features = _get_features,
			.destroy = _destroy,
		},
	);

	return &this->public;
}
