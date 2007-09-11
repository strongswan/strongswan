/**
 * @file status_controller.c
 *
 * @brief Implementation of status_controller_t.
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

#include "status_controller.h"
#include "../manager.h"
#include "../gateway.h"

#include <template.h>

#include <library.h>


typedef struct private_status_controller_t private_status_controller_t;

/**
 * private data of the task manager
 */
struct private_status_controller_t {

	/**
	 * public functions
	 */
	status_controller_t public;
	
	/**
	 * manager instance
	 */
	manager_t *manager;
	
	int count;
	
};

static void ikesalist(private_status_controller_t *this,
					  request_t *request, response_t *response)
{
	char *str;
	gateway_t *gateway;

	gateway = this->manager->select_gateway(this->manager, 0);
	str = gateway->request(gateway,	"<message type=\"request\" id=\"1\">"
										"<query>"
											"<ikesalist/>"
										"</query>"
									"</message>");

	response->set_content_type(response, "text/xml");
	template_t *t = template_create("templates/status/ikesalist.cs");
	t->set(t, "xml", str);
	t->render(t, response);
	t->destroy(t);
	
	free(str);
}

/**
 * redirect to authentication login
 */
static void login(private_status_controller_t *this,
				  request_t *request, response_t *response)
{
	response->redirect(response, "auth/login");
}

/**
 * redirect to gateway selection
 */
static void selection(private_status_controller_t *this,
				  	  request_t *request, response_t *response)
{
	response->redirect(response, "gateway/list");
}

/**
 * Implementation of controller_t.get_name
 */
static char* get_name(private_status_controller_t *this)
{
	return "status";
}

/**
 * Implementation of controller_t.get_handler
 */
static controller_handler_t get_handler(private_status_controller_t *this, char *name)
{
	if (!this->manager->logged_in(this->manager)) return (controller_handler_t)login;
	if (this->manager->select_gateway(this->manager, 0) == NULL) return (controller_handler_t)selection;
	if (streq(name, "ikesalist")) return (controller_handler_t)ikesalist;
	return NULL;
}

/**
 * Implementation of controller_t.destroy
 */
static void destroy(private_status_controller_t *this)
{
	free(this);
}

/*
 * see header file
 */
controller_t *status_controller_create(context_t *context, void *param)
{
	private_status_controller_t *this = malloc_thing(private_status_controller_t);

	this->public.controller.get_name = (char*(*)(controller_t*))get_name;
	this->public.controller.get_handler = (controller_handler_t(*)(controller_t*,char*))get_handler;
	this->public.controller.destroy = (void(*)(controller_t*))destroy;
	
	this->count = 0;
	this->manager = (manager_t*)context;
	
	return &this->public.controller;
}

