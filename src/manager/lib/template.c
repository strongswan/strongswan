/**
 * @file template.c
 *
 * @brief Implementation of template_t.
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

#include "template.h"

#include <ClearSilver/ClearSilver.h>

#include <library.h>

typedef struct private_template_t private_template_t;

/**
 * private data of the task manager
 */
struct private_template_t {

	/**
	 * public functions
	 */
	template_t public;
	
	/**
	 * template file
	 */
	char *file;
	
	/**
	 * clearsilver HDF dataset
	 */
	HDF *hdf;
};

/**
 * clearsilver cs_render callback function
 */
static NEOERR* render_cb(response_t *response, char *str)
{
	response->print(response, str);
	return NULL;
}

/**
 * Implementation of template_t.render.
 */
static void render(private_template_t *this, response_t *response)
{
	NEOERR* err;
	CSPARSE *parse;
	
	hdf_remove_tree(this->hdf, "");
	
	err = cs_init(&parse, this->hdf);
	if (!err)
	{
		err = cs_parse_file(parse, this->file);
		if (!err) 
		{
			err = cs_render(parse, response, (CSOUTFUNC)render_cb);
			if (!err)
			{
				cs_destroy(&parse);
				return;
			}
		}
		cs_destroy(&parse);
	}
	nerr_log_error(err);
	return;
}

/**
 * Implementation of template_t.set.
 */
static void set(private_template_t *this, char *key, char *value)
{
	hdf_set_value(this->hdf, key, value);
}

/**
 * Implementation of template_t.setf.
 */
static void setf(private_template_t *this, char *format, ...)
{
	va_list args;

	va_start(args, format);
	hdf_set_valuevf(this->hdf, format, args);
	va_end(args);
}

/**
 * Implementation of template_t.destroy
 */
static void destroy(private_template_t *this)
{
	hdf_destroy(&this->hdf);
	free(this->file);
	free(this);
}

/*
 * see header file
 */
template_t *template_create(char *file)
{	
	private_template_t *this = malloc_thing(private_template_t);

	this->public.render = (void(*)(template_t*,response_t*))render;
	this->public.set = (void(*)(template_t*, char *, char*))set;
	this->public.setf = (void(*)(template_t*, char *format, ...))setf;
	this->public.destroy = (void(*)(template_t*))destroy;

	this->file = strdup(file);
	this->hdf = NULL;
	
	hdf_init(&this->hdf);
	return &this->public;
}

