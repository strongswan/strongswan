/*
 * Copyright (C) 2006-2008 Martin Willi
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
 *
 * $Id$
 */

#include "printf_hook.h"

#include <utils.h>

typedef struct private_printf_hook_t private_printf_hook_t;

/**
 * private data of printf_hook
 */
struct private_printf_hook_t {

	/**
	 * public functions
	 */
	printf_hook_t public;
};

/**
 * Implementation of printf_hook_t.add_handler.
 */
static void add_handler(private_printf_hook_t *this, char spec, 
						printf_hook_functions_t hook)
{
	register_printf_function(spec, hook.print, hook.arginfo);
}

/**
 * Implementation of printf_hook_t.destroy
 */
static void destroy(private_printf_hook_t *this)
{
	free(this);
}

/*
 * see header file
 */
printf_hook_t *printf_hook_create()
{
	private_printf_hook_t *this = malloc_thing(private_printf_hook_t);
	
	this->public.add_handler = (void(*)(printf_hook_t*, char, printf_hook_functions_t))add_handler;
	this->public.destroy = (void(*)(printf_hook_t*))destroy;
	
	
	return &this->public;
}

