/**
 * @file gateway_controller.c
 *
 * @brief Implementation of gateway_controller_t.
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

#include "gateway_controller.h"
#include "../manager.h"
#include "../gateway.h"

#include <library.h>


typedef struct private_gateway_controller_t private_gateway_controller_t;

/**
 * private data of the gateway_controller
 */
struct private_gateway_controller_t {

	/**
	 * public functions
	 */
	gateway_controller_t public;
	
	/**
	 * manager instance
	 */
	manager_t *manager;
	
};

static void list(private_gateway_controller_t *this, request_t *request)
{
	enumerator_t *enumerator;
	char *name, *address;
	int id, port;
	
	enumerator = this->manager->create_gateway_enumerator(this->manager);
	while (enumerator->enumerate(enumerator, &id, &name, &port, &address))
	{
		request->setf(request, "gateways.%d.name=%s", id, name);
		if (port)
		{
			request->setf(request, "gateways.%d.address=tcp://%s:%d",
						  id, address, port);
		}
		else
		{
			request->setf(request, "gateways.%d.address=unix://%s",
						  id, IPSEC_PIDDIR"/charon.xml");
		}
	}
	enumerator->destroy(enumerator);
	request->set(request, "action", "select");
	request->set(request, "title", "Choose gateway");
	request->render(request, "templates/gateway/list.cs");
}

static void _select(private_gateway_controller_t *this, request_t *request)
{
	char *id;
	
	id = request->get_query_data(request, "gateway");
	if (id)
	{
		if (this->manager->select_gateway(this->manager, atoi(id)))
		{
			request->redirect(request, "ikesa/list");
			return;
		}
	}
	request->redirect(request, "gateway/list");
}

/**
 * Implementation of controller_t.get_name
 */
static char* get_name(private_gateway_controller_t *this)
{
	return "gateway";
}

/**
 * Implementation of controller_t.handle
 */
static void handle(private_gateway_controller_t *this,
				   request_t *request, char *action)
{
	if (!this->manager->logged_in(this->manager))
	{
		return request->redirect(request, "auth/login");
	}
	if (action)
	{
		if (streq(action, "list"))
		{
			return list(this, request);
		}
		else if (streq(action, "select")) 
		{
			return _select(this, request);
		}
	}
	request->redirect(request, "gateway/list");
}


/**
 * Implementation of controller_t.destroy
 */
static void destroy(private_gateway_controller_t *this)
{
	free(this);
}

/*
 * see header file
 */
controller_t *gateway_controller_create(context_t *context, void *param)
{
	private_gateway_controller_t *this = malloc_thing(private_gateway_controller_t);

	this->public.controller.get_name = (char*(*)(controller_t*))get_name;
	this->public.controller.handle = (void(*)(controller_t*,request_t*,char*,char*,char*,char*,char*))handle;
	this->public.controller.destroy = (void(*)(controller_t*))destroy;
	
	this->manager = (manager_t*)context;
	
	return &this->public.controller;
}

