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

METHOD(plugin_t, destroy, void,
	private_af_alg_plugin_t *this)
{
	lib->crypto->remove_hasher(lib->crypto,
					(hasher_constructor_t)af_alg_hasher_create);
	lib->crypto->remove_signer(lib->crypto,
					(signer_constructor_t)af_alg_signer_create);
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
				.destroy = _destroy,
			},
		},
	);

	lib->crypto->add_hasher(lib->crypto, HASH_SHA1,
					(hasher_constructor_t)af_alg_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA224,
					(hasher_constructor_t)af_alg_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA256,
					(hasher_constructor_t)af_alg_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA384,
					(hasher_constructor_t)af_alg_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA512,
					(hasher_constructor_t)af_alg_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_MD5,
					(hasher_constructor_t)af_alg_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_MD4,
					(hasher_constructor_t)af_alg_hasher_create);

	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_MD5_96,
					(signer_constructor_t)af_alg_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_MD5_128,
					(signer_constructor_t)af_alg_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA1_96,
					(signer_constructor_t)af_alg_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA1_128,
					(signer_constructor_t)af_alg_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA1_160,
					(signer_constructor_t)af_alg_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA2_256_96,
					(signer_constructor_t)af_alg_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA2_256_128,
					(signer_constructor_t)af_alg_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA2_256_256,
					(signer_constructor_t)af_alg_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA2_384_192,
					(signer_constructor_t)af_alg_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA2_384_384,
					(signer_constructor_t)af_alg_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_HMAC_SHA2_512_256,
					(signer_constructor_t)af_alg_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_AES_XCBC_96,
					(signer_constructor_t)af_alg_signer_create);
	lib->crypto->add_signer(lib->crypto, AUTH_CAMELLIA_XCBC_96,
					(signer_constructor_t)af_alg_signer_create);

	lib->crypto->add_crypter(lib->crypto, ENCR_DES,
					(crypter_constructor_t)af_alg_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_3DES,
					(crypter_constructor_t)af_alg_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_AES_CBC,
					(crypter_constructor_t)af_alg_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_AES_CTR,
					(crypter_constructor_t)af_alg_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_CAMELLIA_CBC,
					(crypter_constructor_t)af_alg_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_CAMELLIA_CTR,
					(crypter_constructor_t)af_alg_crypter_create);

	return &this->public.plugin;
}
