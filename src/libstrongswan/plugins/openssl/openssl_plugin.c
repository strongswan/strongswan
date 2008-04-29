/*
 * Copyright (C) 2008 Tobias Brunner
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
 *
 * $Id$
 */

#include <openssl/evp.h>

#include "openssl_plugin.h"

#include <library.h>
#include "openssl_crypter.h"
#include "openssl_hasher.h"

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
 * Implementation of openssl_plugin_t.destroy
 */
static void destroy(private_openssl_plugin_t *this)
{
	lib->crypto->remove_crypter(lib->crypto,
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->remove_hasher(lib->crypto,
					(hasher_constructor_t)openssl_hasher_create);
	
	EVP_cleanup();
	
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_openssl_plugin_t *this = malloc_thing(private_openssl_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	OpenSSL_add_all_algorithms();
	
	/* crypter */
	lib->crypto->add_crypter(lib->crypto, ENCR_DES,
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
	lib->crypto->add_crypter(lib->crypto, ENCR_NULL,
					(crypter_constructor_t)openssl_crypter_create);
	lib->crypto->add_crypter(lib->crypto, ENCR_AES_CBC,
					(crypter_constructor_t)openssl_crypter_create);
	
	/* hasher */
	lib->crypto->add_hasher(lib->crypto, HASH_SHA1,
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_MD2,
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_MD5,
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA256,
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA384,
					(hasher_constructor_t)openssl_hasher_create);
	lib->crypto->add_hasher(lib->crypto, HASH_SHA512,
					(hasher_constructor_t)openssl_hasher_create);
	
	return &this->public.plugin;
}
