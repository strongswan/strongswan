/*
 * Copyright (C) 2018-2020 Andreas Steffen
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

#include "oqs_plugin.h"
#include "oqs_kem.h"
#include "oqs_drbg.h"
#include "oqs_public_key.h"
#include "oqs_private_key.h"

#include <library.h>
#include <threading/thread_value.h>

typedef struct private_oqs_plugin_t private_oqs_plugin_t;

/**
 * private data of oqs_plugin
 */
struct private_oqs_plugin_t {

	/**
	 * public functions
	 */
	oqs_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_oqs_plugin_t *this)
{
	return "oqs";
}

METHOD(plugin_t, get_features, int,
	private_oqs_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		/* KEM-based key exchange methods */
		PLUGIN_REGISTER(KE, oqs_kem_create),
			PLUGIN_PROVIDE(KE, KE_KYBER_L1),
			PLUGIN_PROVIDE(KE, KE_KYBER_L3),
			PLUGIN_PROVIDE(KE, KE_KYBER_L5),
			PLUGIN_PROVIDE(KE, KE_FRODO_AES_L1),
			PLUGIN_PROVIDE(KE, KE_FRODO_AES_L3),
			PLUGIN_PROVIDE(KE, KE_FRODO_AES_L5),
			PLUGIN_PROVIDE(KE, KE_FRODO_SHAKE_L1),
			PLUGIN_PROVIDE(KE, KE_FRODO_SHAKE_L3),
			PLUGIN_PROVIDE(KE, KE_FRODO_SHAKE_L5),
			PLUGIN_PROVIDE(KE, KE_BIKE_L1),
			PLUGIN_PROVIDE(KE, KE_BIKE_L3),
			PLUGIN_PROVIDE(KE, KE_BIKE_L5),
			PLUGIN_PROVIDE(KE, KE_HQC_L1),
			PLUGIN_PROVIDE(KE, KE_HQC_L3),
			PLUGIN_PROVIDE(KE, KE_HQC_L5),
		/* private/public keys */
		PLUGIN_REGISTER(PRIVKEY, oqs_private_key_load, TRUE),
			PLUGIN_PROVIDE(PRIVKEY, KEY_DILITHIUM_2),
			PLUGIN_PROVIDE(PRIVKEY, KEY_DILITHIUM_3),
			PLUGIN_PROVIDE(PRIVKEY, KEY_DILITHIUM_5),
			PLUGIN_PROVIDE(PRIVKEY, KEY_FALCON_512),
			PLUGIN_PROVIDE(PRIVKEY, KEY_FALCON_1024),
		PLUGIN_REGISTER(PRIVKEY_GEN, oqs_private_key_gen, FALSE),
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_DILITHIUM_2),
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_DILITHIUM_3),
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_DILITHIUM_5),
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_FALCON_512),
			PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_FALCON_1024),
		PLUGIN_REGISTER(PUBKEY, oqs_public_key_load, TRUE),
			PLUGIN_PROVIDE(PUBKEY, KEY_DILITHIUM_2),
			PLUGIN_PROVIDE(PUBKEY, KEY_DILITHIUM_3),
			PLUGIN_PROVIDE(PUBKEY, KEY_DILITHIUM_5),
			PLUGIN_PROVIDE(PUBKEY, KEY_FALCON_512),
			PLUGIN_PROVIDE(PUBKEY, KEY_FALCON_1024),
			PLUGIN_PROVIDE(PUBKEY, KEY_ANY),
		/* signature schemes, private */
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_DILITHIUM_2),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_DILITHIUM_3),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_DILITHIUM_5),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_FALCON_512),
		PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_FALCON_1024),
		/* signature verification schemes */
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_DILITHIUM_2),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_DILITHIUM_3),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_DILITHIUM_5),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_FALCON_512),
		PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_FALCON_1024),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_oqs_plugin_t *this)
{
	oqs_drbg_deinit();
	free(this);
}

/*
 * see header file
 */
plugin_t *oqs_plugin_create()
{
	private_oqs_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	oqs_drbg_init();

	return &this->public.plugin;
}
