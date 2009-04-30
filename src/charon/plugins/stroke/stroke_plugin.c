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
 */

#include "stroke_plugin.h"

#include <library.h>
#include "stroke_socket.h"

typedef struct private_stroke_plugin_t private_stroke_plugin_t;

/**
 * private data of stroke_plugin
 */
struct private_stroke_plugin_t {

	/**
	 * public functions
	 */
	stroke_plugin_t public;
	
	/**
	 * stroke socket, receives strokes
	 */
	stroke_socket_t *socket;
};

/**
 * Implementation of stroke_plugin_t.destroy
 */
static void destroy(private_stroke_plugin_t *this)
{
	this->socket->destroy(this->socket);
	free(this);
}

/*
 * see header file
 */
plugin_t *plugin_create()
{
	private_stroke_plugin_t *this = malloc_thing(private_stroke_plugin_t);
	
	this->public.plugin.destroy = (void(*)(plugin_t*))destroy;
	
	this->socket = stroke_socket_create();
	if (this->socket == NULL)
	{
		free(this);
		return NULL;
	}
	return &this->public.plugin;
}

