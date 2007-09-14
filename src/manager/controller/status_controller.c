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
	xml_t *node;
	enumerator_t *e1, *e2, *e3, *e4, *e5, *e6, *e7, *e8;
	char *name, *value, *id = "", *section;

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
	
	node = xml_create(str);
	if (node == NULL)
	{
		response->printf(response, "parsing XML failed");
		return;
	}
	
	template_t *t = template_create("templates/status/ikesalist.cs");

	e1 = node->children(node);
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
										else if (streq(name, "childsalist"))
										{
											e6 = node->children(node);
											while (e6->enumerate(e6, &node, &name, &value))
											{
												if (streq(name, "childsa"))
												{
													e7 = node->children(node);
													while (e7->enumerate(e7, &node, &name, &value))
													{
														if (streq(name, "local") ||
															streq(name, "remote"))
														{
															section = name;
															e8 = node->children(node);
															while (e8->enumerate(e8, &node, &name, &value))
															{
																t->setf(t, "ikesas.%s.childsas.%s.%s=%s", id, section, name, value);
															}
															e8->destroy(e8);
														}
													}
													e7->destroy(e7);
												}
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

	t->set(t, "title", "IKE SA overview");
	t->render(t, response);
	t->destroy(t); 
	free(str);
}

/**
 * Implementation of controller_t.get_name
 */
static char* get_name(private_status_controller_t *this)
{
	return "status";
}

/**
 * Implementation of controller_t.handle
 */
static void handle(private_status_controller_t *this,
				   request_t *request, response_t *response, char *action)
{
	if (!this->manager->logged_in(this->manager))
	{
		return response->redirect(response, "auth/login");
	}
	if (this->manager->select_gateway(this->manager, 0) == NULL)
	{
		return response->redirect(response, "gateway/list");
	}
	if (action)
	{
		if (streq(action, "ikesalist"))
		{
			return ikesalist(this, request, response);
		}
	}
	return response->redirect(response, "status/ikesalist");
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
	this->public.controller.handle = (void(*)(controller_t*,request_t*,response_t*,char*,char*,char*,char*,char*))handle;
	this->public.controller.destroy = (void(*)(controller_t*))destroy;
	
	this->manager = (manager_t*)context;
	
	return &this->public.controller;
}

