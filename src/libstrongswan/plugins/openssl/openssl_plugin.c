/*
 * Copyright (C) 2008 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
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

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>

#include "openssl_plugin.h"

#include <library.h>
#include <threading/thread.h>
#include <threading/mutex.h>
#include "openssl_util.h"
#include "openssl_crypter.h"
#include "openssl_hasher.h"
#include "openssl_diffie_hellman.h"
#include "openssl_ec_diffie_hellman.h"
#include "openssl_rsa_private_key.h"
#include "openssl_rsa_public_key.h"
#include "openssl_ec_private_key.h"
#include "openssl_ec_public_key.h"

typedef struct private_openssl_plugin_t private_openssl_plugin_t;

/**
 * private data of openssl_plugin
 */
struct private_openssl_plugin_t {

	/**
	 * public functions
	 */
	openssl_plugin_t public;
};

/**
 * Array of static mutexs, with CRYPTO_num_locks() mutex
 */
static mutex_t **mutex = NULL;

/**
 * Locking callback for static locks
 */
static void locking_function(int mode, int type, const char *file, int line)
{
	if (mutex)
	{
		if (mode & CRYPTO_LOCK)
		{
			mutex[type]->lock(mutex[type]);
		}
		else
		{
			mutex[type]->unlock(mutex[type]);
		}
	}
}

/**
 * Implementation of dynlock
 */
struct CRYPTO_dynlock_value {
	mutex_t *mutex;
};

/**
 * Callback to create a dynamic lock
 */
static struct CRYPTO_dynlock_value *create_function(const char *file, int line)
{
	struct CRYPTO_dynlock_value *lock;

	lock = malloc_thing(struct CRYPTO_dynlock_value);
	lock->mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	return lock;
}

/**
 * Callback to (un-)lock a dynamic lock
 */
static void lock_function(int mode, struct CRYPTO_dynlock_value *lock,
						  const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
	{
		lock->mutex->lock(lock->mutex);
	}
	else
	{
		lock->mutex->unlock(lock->mutex);
	}
}

/**
 * Callback to destroy a dynamic lock
 */
static void destroy_function(struct CRYPTO_dynlock_value *lock,
							 const char *file, int line)
{
	lock->mutex->destroy(lock->mutex);
	free(lock);
}

/**
 * Thread-ID callback function
 */
static unsigned long id_function(void)
{
	return (unsigned long)thread_current_id();
}

/**
 * initialize OpenSSL for multi-threaded use
 */
static void threading_init()
{
	int i, num_locks;

	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_locking_callback(locking_function);

	CRYPTO_set_dynlock_create_callback(create_function);
	CRYPTO_set_dynlock_lock_callback(lock_function);
	CRYPTO_set_dynlock_destroy_callback(destroy_function);

	num_locks = CRYPTO_num_locks();
	mutex = malloc(sizeof(mutex_t*) * num_locks);
	for (i = 0; i < num_locks; i++)
	{
		mutex[i] = mutex_create(MUTEX_TYPE_DEFAULT);
	}
}

/**
 * cleanup OpenSSL threading locks
 */
static void threading_cleanup()
{
	int i, num_locks;

	num_locks = CRYPTO_num_locks();
	for (i = 0; i < num_locks; i++)
	{
		mutex[i]->destroy(mutex[i]);
	}
	free(mutex);
	mutex = NULL;
}

/**
 * Implementation of openssl_plugin_t.destroy
 */
static void destroy(private_openssl_plugin_t *this)
{
	lib->crypto->remove_crypter(lib->crypto,
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->remove_hasher(lib->crypto,
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->remove_dh(lib->crypto,
					(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->remove_dh(lib->crypto,
					(dh_constructor_t)openssl_ec_diffie_hellman_create);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_rsa_private_key_load);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_rsa_private_key_gen);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_rsa_private_key_connect);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_rsa_public_key_load);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_ec_private_key_load);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_ec_private_key_gen);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_ec_public_key_load);

	ENGINE_cleanup();
	EVP_cleanup();
	CONF_modules_free();

	threading_cleanup();

	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_openssl_plugin_t *this = malloc_thing(private_openssl_plugin_t);

	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;

	threading_init();

	OPENSSL_config(NULL);
	OpenSSL_add_all_algorithms();

	/* activate support for hardware accelerators */
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	/* crypter */
	lib->crypto->add_crypter(lib->crypto, ENCR_AES_CBC,
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_CAMELLIA_CBC,
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_3DES,
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_RC5,
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_IDEA,
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_CAST,
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_BLOWFISH,
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_DES,
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_DES_ECB,
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_NULL,
					(crypter_constructor_t)openssl_crypter_create);

	/* hasher */
	lib->crypto->add_hasher(lib->crypto, HASH_SHA1,
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_MD2,
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_MD4,
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_MD5,
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA224,
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA256,
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA384,
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA512,
					(hasher_constructor_t)openssl_hasher_create);

	/* (ec) diffie hellman */
	lib->crypto->add_dh(lib->crypto, MODP_2048_BIT,
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_1536_BIT,
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, ECP_256_BIT,
						(dh_constructor_t)openssl_ec_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, ECP_384_BIT,
						(dh_constructor_t)openssl_ec_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, ECP_521_BIT,
						(dh_constructor_t)openssl_ec_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, ECP_224_BIT,
						(dh_constructor_t)openssl_ec_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, ECP_192_BIT,
						(dh_constructor_t)openssl_ec_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_3072_BIT,
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_4096_BIT,
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_6144_BIT,
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_8192_BIT,
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_1024_BIT,
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_768_BIT,
						(dh_constructor_t)openssl_diffie_hellman_create);

	/* rsa */
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
					(builder_function_t)openssl_rsa_private_key_load);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
					(builder_function_t)openssl_rsa_private_key_gen);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
					(builder_function_t)openssl_rsa_private_key_connect);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
					(builder_function_t)openssl_rsa_public_key_load);

	/* ec */
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_ECDSA,
					(builder_function_t)openssl_ec_private_key_load);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_ECDSA,
					(builder_function_t)openssl_ec_private_key_gen);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_ECDSA,
					(builder_function_t)openssl_ec_public_key_load);

	return &this->public.plugin;
}

