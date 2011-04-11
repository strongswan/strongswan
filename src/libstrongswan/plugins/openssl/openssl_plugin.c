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

#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include "openssl_plugin.h"

#include <library.h>
#include <debug.h>
#include <threading/thread.h>
#include <threading/mutex.h>
#include "openssl_util.h"
#include "openssl_crypter.h"
#include "openssl_hasher.h"
#include "openssl_sha1_prf.h"
#include "openssl_diffie_hellman.h"
#include "openssl_ec_diffie_hellman.h"
#include "openssl_rsa_private_key.h"
#include "openssl_rsa_public_key.h"
#include "openssl_ec_private_key.h"
#include "openssl_ec_public_key.h"
#include "openssl_x509.h"
#include "openssl_crl.h"

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
 * Seed the OpenSSL RNG, if required
 */
static bool seed_rng()
{
	rng_t *rng = NULL;
	char buf[32];

	while (RAND_status() != 1)
	{
		if (!rng)
		{
			rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
			if (!rng)
			{
				return FALSE;
			}
		}
		rng->get_bytes(rng, sizeof(buf), buf);
		RAND_seed(buf, sizeof(buf));
	}
	DESTROY_IF(rng);
	return TRUE;
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

METHOD(plugin_t, get_name, char*,
	private_openssl_plugin_t *this)
{
	return "openssl";
}

METHOD(plugin_t, destroy, void,
	private_openssl_plugin_t *this)
{
	lib->crypto->remove_crypter(lib->crypto,
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->remove_hasher(lib->crypto,
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->remove_prf(lib->crypto,
					(prf_constructor_t)openssl_sha1_prf_create);
	lib->crypto->remove_dh(lib->crypto,
					(dh_constructor_t)openssl_diffie_hellman_create);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_rsa_private_key_load);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_rsa_private_key_gen);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_rsa_private_key_connect);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_rsa_public_key_load);
#ifndef OPENSSL_NO_EC
	lib->crypto->remove_dh(lib->crypto,
					(dh_constructor_t)openssl_ec_diffie_hellman_create);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_ec_private_key_load);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_ec_private_key_gen);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_ec_public_key_load);
#endif /* OPENSSL_NO_EC */
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_x509_load);
	lib->creds->remove_builder(lib->creds,
					(builder_function_t)openssl_crl_load);

#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif /* OPENSSL_NO_ENGINE */
	EVP_cleanup();
	CONF_modules_free();

	threading_cleanup();

	free(this);
}

/*
 * see header file
 */
plugin_t *openssl_plugin_create()
{
	private_openssl_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
	);

	threading_init();

	OPENSSL_config(NULL);
	OpenSSL_add_all_algorithms();

#ifndef OPENSSL_NO_ENGINE
	/* activate support for hardware accelerators */
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
#endif /* OPENSSL_NO_ENGINE */

	if (!seed_rng())
	{
		DBG1(DBG_CFG, "no RNG found to seed OpenSSL");
		destroy(this);
		return NULL;
	}

	/* crypter */
	lib->crypto->add_crypter(lib->crypto, ENCR_AES_CBC, get_name(this),
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_CAMELLIA_CBC, get_name(this),
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_3DES, get_name(this),
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_RC5, get_name(this),
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_IDEA, get_name(this),
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_CAST, get_name(this),
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_BLOWFISH, get_name(this),
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_DES, get_name(this),
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_DES_ECB, get_name(this),
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_NULL, get_name(this),
					(crypter_constructor_t)openssl_crypter_create);

	/* hasher */
	lib->crypto->add_hasher(lib->crypto, HASH_SHA1, get_name(this),
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_MD2, get_name(this),
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_MD4, get_name(this),
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_MD5, get_name(this),
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA224, get_name(this),
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA256, get_name(this),
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA384, get_name(this),
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA512, get_name(this),
					(hasher_constructor_t)openssl_hasher_create);

	/* prf */
	lib->crypto->add_prf(lib->crypto, PRF_KEYED_SHA1, get_name(this),
					(prf_constructor_t)openssl_sha1_prf_create);

	/* (ec) diffie hellman */
	lib->crypto->add_dh(lib->crypto, MODP_2048_BIT, get_name(this),
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_2048_224, get_name(this),
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_2048_256, get_name(this),
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_1536_BIT, get_name(this),
						(dh_constructor_t)openssl_diffie_hellman_create);
#ifndef OPENSSL_NO_EC
	lib->crypto->add_dh(lib->crypto, ECP_256_BIT, get_name(this),
						(dh_constructor_t)openssl_ec_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, ECP_384_BIT, get_name(this),
						(dh_constructor_t)openssl_ec_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, ECP_521_BIT, get_name(this),
						(dh_constructor_t)openssl_ec_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, ECP_224_BIT, get_name(this),
						(dh_constructor_t)openssl_ec_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, ECP_192_BIT, get_name(this),
						(dh_constructor_t)openssl_ec_diffie_hellman_create);
#endif /* OPENSSL_NO_EC */
	lib->crypto->add_dh(lib->crypto, MODP_3072_BIT, get_name(this),
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_4096_BIT, get_name(this),
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_6144_BIT, get_name(this),
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_8192_BIT, get_name(this),
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_1024_BIT, get_name(this),
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_1024_160, get_name(this),
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_768_BIT, get_name(this),
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_CUSTOM, get_name(this),
						(dh_constructor_t)openssl_diffie_hellman_create);

	/* rsa */
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_RSA, TRUE,
					(builder_function_t)openssl_rsa_private_key_load);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_RSA, FALSE,
					(builder_function_t)openssl_rsa_private_key_gen);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_ANY, FALSE,
					(builder_function_t)openssl_rsa_private_key_connect);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_RSA, TRUE,
					(builder_function_t)openssl_rsa_public_key_load);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_ANY, FALSE,
					(builder_function_t)openssl_rsa_public_key_load);

#ifndef OPENSSL_NO_EC
	/* ecdsa */
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_ECDSA, TRUE,
					(builder_function_t)openssl_ec_private_key_load);
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_ECDSA, FALSE,
					(builder_function_t)openssl_ec_private_key_gen);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_ECDSA, TRUE,
					(builder_function_t)openssl_ec_public_key_load);
#endif /* OPENSSL_NO_EC */

	/* X509 certificates */
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509, TRUE,
					(builder_function_t)openssl_x509_load);
	lib->creds->add_builder(lib->creds, CRED_CERTIFICATE, CERT_X509_CRL, TRUE,
					(builder_function_t)openssl_crl_load);

	return &this->public.plugin;
}

