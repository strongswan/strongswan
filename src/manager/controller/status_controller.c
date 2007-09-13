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
#include <xml.h>

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
};

static void ikesalist(private_status_controller_t *this,
					  request_t *request, response_t *response)
{
	char *str;
	gateway_t *gateway;
	xml_t *doc, *node;
	enumerator_t *e1, *e2, *e3, *e4, *e5, *e6;
	char *name, *value, *id, *section;

	gateway = this->manager->select_gateway(this->manager, 0);
	str = gateway->request(gateway,	"<message type=\"request\" id=\"1\">"
										"<query>"
											"<ikesalist/>"
										"</query>"
									"</message>");
	if (str == NULL)
	{
		response->printf(response, "gateway did not respond");
		return;
	}
	
	doc = xml_create(str);
	if (doc == NULL)
	{
		response->printf(response, "parsing XML failed");
		return;
	}
	
	template_t *t = template_create("templates/status/ikesalist.cs");

	e1 = doc->children(doc);
	while (e1->enumerate(e1, &node, &name, &value))
	{
		if (streq(name, "message"))
		{
			e2 = node->children(node);
			while (e2->enumerate(e2, &node, &name, &value))
			{
				if (streq(name, "query"))
				{
					e3 = node->children(node);
					while (e3->enumerate(e3, &node, &name, &value))
					{
						if (streq(name, "ikesalist"))
						{
							e4 = node->children(node);
							while (e4->enumerate(e4, &node, &name, &value))
							{
								if (streq(name, "ikesa"))
								{
									e5 = node->children(node);
									while (e5->enumerate(e5, &node, &name, &value))
									{
										if (streq(name, "id"))
										{
											id = value;	
										}
										else if(streq(name, "local") ||
												streq(name, "remote"))
										{
											section = name;
											e6 = node->children(node);
											while (e6->enumerate(e6, &node, &name, &value))
											{
												t->setf(t, "ikesas.%s.%s.%s=%s", id, section, name, value);
											}
											e6->destroy(e6);
										}
										else
										{
											t->setf(t, "ikesas.%s.%s=%s", id, name, value);
										}
									}
									e5->destroy(e5);
								}
							}
							e4->destroy(e4);
						}
					}
					e3->destroy(e3);
				}
			}
			e2->destroy(e2);
		}
	}
	e1->destroy(e1);

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
	
	this->manager = (manager_t*)context;
	
	return &this->public.controller;
}

