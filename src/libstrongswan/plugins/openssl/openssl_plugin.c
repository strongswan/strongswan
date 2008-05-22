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
#include "openssl_diffie_hellman.h"
#include "openssl_ec_diffie_hellman.h"
#include "openssl_rsa_private_key.h"
#include "openssl_rsa_public_key.h"

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
	lib->crypto->remove_dh(lib->crypto, 
					(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->remove_dh(lib->crypto, 
					(dh_constructor_t)openssl_ec_diffie_hellman_create);
	lib->creds->remove_builder(lib->creds,
					(builder_constructor_t)openssl_rsa_private_key_builder);
	lib->creds->remove_builder(lib->creds,
					(builder_constructor_t)openssl_rsa_public_key_builder);
	
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
	
	/* diffie hellman */
	lib->crypto->add_dh(lib->crypto, MODP_768_BIT, 
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_1024_BIT,
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_1536_BIT, 
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_2048_BIT, 
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_3072_BIT, 
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_4096_BIT, 
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_6144_BIT, 
						(dh_constructor_t)openssl_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_8192_BIT, 
						(dh_constructor_t)openssl_diffie_hellman_create);
	
	/* ec diffie hellman */
	lib->crypto->add_dh(lib->crypto, ECP_256_BIT,
						(dh_constructor_t)openssl_ec_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, ECP_384_BIT,
						(dh_constructor_t)openssl_ec_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, ECP_521_BIT,
						(dh_constructor_t)openssl_ec_diffie_hellman_create);
	
	/* rsa */
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
						(builder_constructor_t)openssl_rsa_private_key_builder);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
						(builder_constructor_t)openssl_rsa_public_key_builder);
	
	return &this->public.plugin;
}
