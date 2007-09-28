/**
 * @file session.c
 *
 * @brief Implementation of session_t.
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

#define _GNU_SOURCE

#include "session.h"

#include <string.h>
#include <fcgiapp.h>
#include <stdio.h>

#include <utils/linked_list.h>
#include <utils/randomizer.h>

typedef struct private_session_t private_session_t;

/**
 * private data of the task manager
 */
struct private_session_t {

	/**
	 * public functions
	 */
	session_t public;
	
	/**
	 * session ID
	 */
	char *sid;
	
	/**
	 * list of controller instances controller_t
	 */
	linked_list_t *controllers;
	
	/**
	 * user defined session context
	 */
	context_t *context;
};

/**
 * Implementation of session_t.load_controller.
 */
static void add_controller(private_session_t *this, controller_t *controller)
{
	this->controllers->insert_last(this->controllers, controller);
}

/**
 * Create a session ID and a cookie
 */
static void create_sid(private_session_t *this, request_t *request)
{
	char buf[16];
	chunk_t chunk = chunk_from_buf(buf);
	randomizer_t *randomizer = randomizer_create();
	
	randomizer->get_pseudo_random_bytes(randomizer, sizeof(buf), buf);
	this->sid = chunk_to_hex(chunk, FALSE);
	request->add_cookie(request, "SID", this->sid);
	randomizer->destroy(randomizer);
}

/**
 * Implementation of session_t.process.
 */
static void process(private_session_t *this, request_t *request)
{
	char *pos, *start, *param[6] = {NULL, NULL, NULL, NULL, NULL, NULL};
	iterator_t *iterator;
	bool handled = FALSE;
	controller_t *current;
	int i = 0;
	
	if (this->sid == NULL)
	{
		create_sid(this, request);
	}
	
	start = request->get_path(request);
	if (start)
	{
		if (*start == '/') start++;
		while ((pos = strchr(start, '/')) != NULL && i < 5)
		{
			param[i++] = strndup(start, pos - start);
			start = pos + 1;
		}
		param[i] = strdup(start);
		iterator = this->controllers->create_iterator(this->controllers, TRUE);
		while (iterator->iterate(iterator, (void**)&current))
		{
			if (streq(current->get_name(current), param[0]))
			{	
				current->handle(current, request, param[1], param[2], param[3],
								param[4], param[5]);
				handled = TRUE;
				break;
			}
		}
		iterator->destroy(iterator);
		for (i = 0; i < 6; i++)
		{
			free(param[i]);
		}
	}
	if (!handled)
	{
		if (this->controllers->get_first(this->controllers,
										 (void**)&current) == SUCCESS)
		{
			request->redirect(request, current->get_name(current));
		}
	}
}

/**
 * Implementation of session_t.get_sid.
 */
static char* get_sid(private_session_t *this)
{
	return this->sid;
}

/**
 * Implementation of session_t.destroy
 */
static void destroy(private_session_t *this)
{
	this->controllers->destroy_offset(this->controllers, offsetof(controller_t, destroy));
	if (this->context) this->context->destroy(this->context);
	free(this->sid);
	free(this);
}

/*
 * see header file
 */
session_t *session_create(context_t *context)
{
	private_session_t *this = malloc_thing(private_session_t);

	this->public.add_controller = (void(*)(session_t*, controller_t*))add_controller;
	this->public.process = (void(*)(session_t*,request_t*))process;
	this->public.get_sid = (char*(*)(session_t*))get_sid;
	this->public.destroy = (void(*)(session_t*))destroy;

	this->sid = NULL;
	this->controllers = linked_list_create();
	this->context = context;
	
	return &this->public;
}

