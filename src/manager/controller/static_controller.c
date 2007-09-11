/**
 * @file static_controller.c
 *
 * @brief Implementation of static_controller_t.
 *
 */

/*
 * Copyright (C) 2007 Martin Willi
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

#include "static_controller.h"
#include "../manager.h"
#include "../gateway.h"

#include <template.h>

#include <library.h>


typedef struct private_static_controller_t private_static_controller_t;

/**
 * private data of the task manager
 */
struct private_static_controller_t {

	/**
	 * public functions
	 */
	static_controller_t public;
	
	/**
	 * manager instance
	 */
	manager_t *manager;
	
};

/**
 * serve style.css
 */
static void style(private_static_controller_t *this,
				  request_t *request, response_t *response)
{
	template_t *t = template_create("templates/static/style.css");
	response->set_content_type(response, "text/css");
	t->render(t, response);
	t->destroy(t);
}

/**
 * Implementation of controller_t.get_name
 */
static char* get_name(private_static_controller_t *this)
{
	return "static";
}

/**
 * Implementation of controller_t.get_handler
 */
static controller_handler_t get_handler(private_static_controller_t *this, char *name)
{
	if (streq(name, "style.css")) return (controller_handler_t)style;
	return NULL;
}

/**
 * Implementation of controller_t.destroy
 */
static void destroy(private_static_controller_t *this)
{
	free(this);
}

/*
 * see header file
 */
controller_t *static_controller_create(context_t *context, void *param)
{
	private_static_controller_t *this = malloc_thing(private_static_controller_t);

	this->public.controller.get_name = (char*(*)(controller_t*))get_name;
	this->public.controller.get_handler = (controller_handler_t(*)(controller_t*,char*))get_handler;
	this->public.controller.destroy = (void(*)(controller_t*))destroy;
	
	this->manager = (manager_t*)context;
	
	return &this->public.controller;
}

