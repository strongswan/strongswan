/*
 * Copyright (C) 2008-2009 Martin Willi
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

#include "agent_plugin.h"

#include <library.h>
#include "agent_private_key.h"

typedef struct private_agent_plugin_t private_agent_plugin_t;

/**
 * private data of agent_plugin
 */
struct private_agent_plugin_t {

	/**
	 * public functions
	 */
	agent_plugin_t public;
};

/**
 * Implementation of agent_plugin_t.agenttroy
 */
static void destroy(private_agent_plugin_t *this)
{
	lib->creds->remove_builder(lib->creds,
							   (builder_function_t)agent_private_key_open);
	free(this);
}

/*
 * see header file
 */
plugin_t *agent_plugin_create()
{
	private_agent_plugin_t *this = malloc_thing(private_agent_plugin_t);

	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;

	lib->creds->add_builder(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
							(builder_function_t)agent_private_key_open);
	return &this->public.plugin;
}

