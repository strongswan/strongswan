/*
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
 *
 * $Id$
 */

#include "gmp_plugin.h"

#include <library.h>
#include "gmp_diffie_hellman.h"
#include "gmp_rsa_private_key.h"
#include "gmp_rsa_public_key.h"

typedef struct private_gmp_plugin_t private_gmp_plugin_t;

/**
 * private data of gmp_plugin
 */
struct private_gmp_plugin_t {

	/**
	 * public functions
	 */
	gmp_plugin_t public;
};

/**
 * Implementation of gmp_plugin_t.gmptroy
 */
static void destroy(private_gmp_plugin_t *this)
{
	lib->crypto->remove_dh(lib->crypto,
						(dh_constructor_t)gmp_diffie_hellman_create);
	lib->creds->remove_builder(lib->creds,
						(builder_constructor_t)gmp_rsa_private_key_builder);
	lib->creds->remove_builder(lib->creds,
						(builder_constructor_t)gmp_rsa_public_key_builder);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_gmp_plugin_t *this = malloc_thing(private_gmp_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	lib->crypto->add_dh(lib->crypto, MODP_2048_BIT, 
						(dh_constructor_t)gmp_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_1536_BIT, 
						(dh_constructor_t)gmp_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_3072_BIT, 
						(dh_constructor_t)gmp_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_4096_BIT, 
						(dh_constructor_t)gmp_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_6144_BIT, 
						(dh_constructor_t)gmp_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_8192_BIT, 
						(dh_constructor_t)gmp_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_1024_BIT,
						(dh_constructor_t)gmp_diffie_hellman_create);
	lib->crypto->add_dh(lib->crypto, MODP_768_BIT, 
						(dh_constructor_t)gmp_diffie_hellman_create);
	
	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
						(builder_constructor_t)gmp_rsa_private_key_builder);
	lib->creds->add_builder(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
						(builder_constructor_t)gmp_rsa_public_key_builder);
	
	return &this->public.plugin;
}

