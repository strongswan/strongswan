/**
 * @file response.c
 *
 * @brief Implementation of response_t.
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

#include "response.h"

#include <stdlib.h>
#include <stdarg.h>

#include <utils/linked_list.h>

typedef struct {
	char *name;
	char *value;
} name_value_t;

/**
 * create name value pair
 */
static name_value_t *name_value_create(char *name, char *value)
{
	name_value_t *this = malloc_thing(name_value_t);
	
	this->name = strdup(name);
	this->value = strdup(value);
	
	return this;
}

/**
 * destroy a name value pair
 */
static void name_value_destroy(name_value_t *this)
{
	free(this->name);
	free(this->value);
	free(this);
}

typedef struct private_response_t private_response_t;

/**
 * private data of the task manager
 */
struct private_response_t {

	/**
	 * public functions
	 */
	response_t public;
	
	/**
	 * the associated fcgi request
	 */
	FCGX_Request *req;
	
	/**
	 * Content type
	 */
	char *content_type;
	
	/**
	 * list of cookies (name_value_t)
	 */
	linked_list_t *cookies;
	
	/**
	 * list of custom headers (name_value_t)
	 */
	linked_list_t *headers;
	
	/**
	 * headers already written?
	 */
	bool started;
};

/**
 * write the headers, if not already written
 */
static void write_headers(private_response_t *this)
{
	iterator_t *iterator;
	name_value_t *current;
	
	FCGX_FPrintF(this->req->out, "Content-type: %s\n", this->content_type);
	iterator = this->cookies->create_iterator(this->cookies, TRUE);
	while (iterator->iterate(iterator, (void**)&current))
	{
		FCGX_FPrintF(this->req->out, "Set-Cookie: %s=%s; path=%s\n",
					 current->name, current->value,
					 FCGX_GetParam("SCRIPT_NAME", this->req->envp));
	}
	iterator->destroy(iterator);
	iterator = this->cookies->create_iterator(this->headers, TRUE);
	while (iterator->iterate(iterator, (void**)&current))
	{
		FCGX_FPrintF(this->req->out, "%s: %s\n",
					 current->name, current->value);
	}
	iterator->destroy(iterator);
	FCGX_PutChar('\n', this->req->out);
	this->started = TRUE;
}

/**
 * Implementation of response_t.print.
 */
static void print_(private_response_t *this, char *str)
{
	if (!this->started)
	{
		write_headers(this);
	}
	FCGX_PutS(str, this->req->out);
}

/**
 * Implementation of response_t.printf.
 */
static void printf_(private_response_t *this, char *format, ...)
{
	va_list args;
	
	if (!this->started)
	{
		write_headers(this);
	}
	
	va_start(args, format);
	FCGX_VFPrintF(this->req->out, format, args);
    va_end(args);
}
	
/**
 * Implementation of response_t.add_header.
 */
static void add_header(private_response_t *this, char *name, char *value)
{
	this->headers->insert_last(this->headers, name_value_create(name, value));
}

/**
 * Implementation of response_t.set_content_type.
 */
static void set_content_type(private_response_t *this, char *type)
{
	free(this->content_type);
	this->content_type = strdup(type);
}

/**
 * Implementation of response_t.add_cookie.
 */
static void add_cookie(private_response_t *this, char *name, char *value)
{
	this->cookies->insert_last(this->cookies, name_value_create(name, value));
}
	
/**
 * Implementation of response_t.redirect.
 */
static void redirect(private_response_t *this, char *location)
{
	FCGX_FPrintF(this->req->out, "Status: 303 See Other\n");
	FCGX_FPrintF(this->req->out, "Location: %s%s%s\n\n",
				 FCGX_GetParam("SCRIPT_NAME", this->req->envp),
				 *location == '/' ? "" : "/", location);
}


/**
 * Implementation of response_t.get_base.
 */
static char* get_base(private_response_t *this)
{
	return FCGX_GetParam("SCRIPT_NAME", this->req->envp);
}

/**
 * Implementation of response_t.destroy
 */
static void destroy(private_response_t *this)
{
	this->headers->destroy_function(this->headers, (void*)name_value_destroy);
	this->cookies->destroy_function(this->cookies, (void*)name_value_destroy);
	free(this->content_type);
	free(this);
}

/*
 * see header file
 */
response_t *response_create(FCGX_Request *request)
{
	private_response_t *this = malloc_thing(private_response_t);

	this->public.print = (void(*)(response_t*, char *str))print_;
	this->public.printf = (void(*)(response_t*, char *format, ...))printf_;
	this->public.add_header = (void(*)(response_t*, char *name, char *value))add_header;
	this->public.set_content_type = (void(*)(response_t*, char *type))set_content_type;
	this->public.add_cookie = (void(*)(response_t*, char *name, char *value))add_cookie;
	this->public.redirect = (void(*)(response_t*, char *location))redirect;
	this->public.get_base = (char*(*)(response_t*))get_base;
	this->public.destroy = (void(*)(response_t*))destroy;
	
	this->req = request;
	this->headers = linked_list_create();
	this->cookies = linked_list_create();
	this->content_type = strdup("text/html");
	this->started = FALSE;
	
	return &this->public;
}

