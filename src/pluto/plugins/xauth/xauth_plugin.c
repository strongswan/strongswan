/*
 * Copyright (C) 2010 Andreas Steffen
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

#include <pluto.h>

#include "xauth_plugin.h"
#include "xauth_default_provider.h"
#include "xauth_default_verifier.h"
/**
 * Implementation of plugin_t.destroy
 */
static void destroy(xauth_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *xauth_plugin_create()
{
	xauth_plugin_t *this = malloc_thing(xauth_plugin_t);

	this->plugin.destroy = (void(*)(plugin_t*))destroy;

	pluto->xauth->add_provider(pluto->xauth, xauth_default_provider_create());
	pluto->xauth->add_verifier(pluto->xauth, xauth_default_verifier_create());

	return &this->plugin;
}

