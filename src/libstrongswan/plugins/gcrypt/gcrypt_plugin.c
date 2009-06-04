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

#include <library.h>
#include <debug.h>

#include <errno.h>
#include <gcrypt.h>
#include <pthread.h>

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
 * Thread callback implementations for pthread
 */
GCRY_THREAD_OPTION_PTHREAD_IMPL;

/**
 * Implementation of gcrypt_plugin_t.destroy
 */
static void destroy(private_gcrypt_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_gcrypt_plugin_t *this;
	
	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	
	if (!gcry_check_version(GCRYPT_VERSION))
	{
		DBG1("libgcrypt version mismatch");
		return NULL;
	}
	
	/* we currently do not use secure memory */
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	
	this = malloc_thing(private_gcrypt_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	return &this->public.plugin;
}

