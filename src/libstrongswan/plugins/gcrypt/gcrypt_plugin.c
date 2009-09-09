/*
 * Copyright (C) 2009 Martin Willi
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

#include "gcrypt_plugin.h"

#include "gcrypt_hasher.h"
#include "gcrypt_crypter.h"
#include "gcrypt_rng.h"
#include "gcrypt_dh.h"
#include "gcrypt_rsa_private_key.h"
#include "gcrypt_rsa_public_key.h"

#include <library.h>
#include <debug.h>
#include <utils/mutex.h>

#include <errno.h>
#include <gcrypt.h>

typedef struct private_gcrypt_plugin_t private_gcrypt_plugin_t;

/**
 * private data of gcrypt_plugin
 */
struct private_gcrypt_plugin_t {

	/**
	 * public functions
	 */
	gcrypt_plugin_t public;
};

/**
 * gcrypt mutex initialization wrapper
 */
static int mutex_init(void **lock)
{
	*lock = mutex_create(MUTEX_TYPE_DEFAULT);
	return 0;
}

/**
 * gcrypt mutex cleanup wrapper
 */
static int mutex_destroy(void **lock)
{
	mutex_t *mutex = *lock;

	mutex->destroy(mutex);
	return 0;
}

/**
 * gcrypt mutex lock wrapper
 */
static int mutex_lock(void **lock)
{
	mutex_t *mutex = *lock;

	mutex->lock(mutex);
	return 0;
}

/**
 * gcrypt mutex unlock wrapper
 */
static int mutex_unlock(void **lock)
{
	mutex_t *mutex = *lock;

	mutex->unlock(mutex);
	return 0;
}

/**
 * gcrypt locking functions using our mutex_t
 */
static struct gcry_thread_cbs thread_functions = {
	GCRY_THREAD_OPTION_USER, NULL,
	mutex_init, mutex_destroy, mutex_lock, mutex_unlock,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

/**
 * Implementation of gcrypt_plugin_t.destroy
 */
static void destroy(private_gcrypt_plugin_t *this)
{
	lib->crypto->remove_hasher(lib->crypto,
					(hasher_constructor_t)gcrypt_hasher_create);
	lib->crypto->remove_crypter(lib->crypto,
					(crypter_constructor_t)gcrypt_crypter_create);
	lib->crypto->remove_rng(lib->crypto,
					(rng_constructor_t)gcrypt_rng_create);
	lib->crypto->remove_dh(lib->crypto,
					(dh_constructor_t)gcrypt_dh_create);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)gcrypt_rsa_private_key_gen);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)gcrypt_rsa_private_key_load);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)gcrypt_rsa_public_key_load);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_gcrypt_plugin_t *this;

	gcry_control(GCRYCTL_SET_THREAD_CBS, &thread_functions);

	if (!gcry_check_version(GCRYPT_VERSION))
	{
		DBG1("libgcrypt version mismatch");
		return NULL;
	}

	/* we currently do not use secure memory */
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	if (lib->settings->get_bool(lib->settings,
							"libstrongswan.plugins.gcrypt.quick_random", FALSE))
	{
		gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0);
	}
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

	this = malloc_thing(private_gcrypt_plugin_t);

	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;

	/* hashers */
	lib->crypto->add_hasher(lib->crypto, HASH_SHA1,
					(hasher_constructor_t)gcrypt_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_MD4,
					(hasher_constructor_t)gcrypt_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_MD5,
					(hasher_constructor_t)gcrypt_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA224,
					(hasher_constructor_t)gcrypt_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA256,
					(hasher_constructor_t)gcrypt_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA384,
					(hasher_constructor_t)gcrypt_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA512,
					(hasher_constructor_t)gcrypt_hasher_create);

	/* crypters */
	lib->crypto->add_crypter(lib->crypto, ENCR_3DES,
					(crypter_constructor_t)gcrypt_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_CAST,
					(crypter_constructor_t)gcrypt_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_BLOWFISH,
					(crypter_constructor_t)gcrypt_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_DES,
					(crypter_constructor_t)gcrypt_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_DES_ECB,
					(crypter_constructor_t)gcrypt_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_AES_CBC,
					(crypter_constructor_t)gcrypt_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_CAMELLIA_CBC,
					(crypter_constructor_t)gcrypt_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_SERPENT_CBC,
					(crypter_constructor_t)gcrypt_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_TWOFISH_CBC,
					(crypter_constructor_t)gcrypt_crypter_create);

	/* random numbers */
	lib->crypto->add_rng(lib->crypto, RNG_WEAK,
						 (rng_constructor_t)gcrypt_rng_create);
	lib->crypto->add_rng(lib->crypto, RNG_STRONG,
						 (rng_constructor_t)gcrypt_rng_create);
	lib->crypto->add_rng(lib->crypto, RNG_TRUE,
						 (rng_constructor_t)gcrypt_rng_create);

	/* diffie hellman groups, using modp */
	lib->crypto->add_dh(lib->crypto, MODP_2048_BIT,
					(dh_constructor_t)gcrypt_dh_create);
	lib->crypto->add_dh(lib->crypto, MODP_1536_BIT,
					(dh_constructor_t)gcrypt_dh_create);
	lib->crypto->add_dh(lib->crypto, MODP_3072_BIT,
					(dh_constructor_t)gcrypt_dh_create);
	lib->crypto->add_dh(lib->crypto, MODP_4096_BIT,
					(dh_constructor_t)gcrypt_dh_create);
	lib->crypto->add_dh(lib->crypto, MODP_6144_BIT,
					(dh_constructor_t)gcrypt_dh_create);
	lib->crypto->add_dh(lib->crypto, MODP_8192_BIT,
					(dh_constructor_t)gcrypt_dh_create);
	lib->crypto->add_dh(lib->crypto, MODP_1024_BIT,
					(dh_constructor_t)gcrypt_dh_create);
	lib->crypto->add_dh(lib->crypto, MODP_768_BIT,
					(dh_constructor_t)gcrypt_dh_create);

	/* RSA */
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
					(builder_function_t)gcrypt_rsa_private_key_gen);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
					(builder_function_t)gcrypt_rsa_private_key_load);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
					(builder_function_t)gcrypt_rsa_public_key_load);

	return &this->public.plugin;
}

