/*
 * Copyright (C) 2010 Andreas Steffen
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

#include "pluto.h"

#include <debug.h>

typedef struct private_pluto_t private_pluto_t;

/**
 * Private additions to pluto_t.
 */
struct private_pluto_t {

	/**
	 * Public members of pluto_t.
	 */
	pluto_t public;
};

/**
 * Single instance of pluto_t.
 */
pluto_t *pluto;

/**
 * Described in header.
 */
void pluto_deinit()
{
	private_pluto_t *this = (private_pluto_t*)pluto;
	this->public.xauth->destroy(this->public.xauth);
	free(this);
	pluto = NULL;
}

/**
 * Described in header.
 */
bool pluto_init(char *file)
{
	private_pluto_t *this;

	INIT(this,
		.public = {
			.xauth = xauth_manager_create(),
		},
	);
	pluto = &this->public;

	if (lib->integrity &&
		!lib->integrity->check_file(lib->integrity, "pluto", file))
	{
		DBG1(DBG_LIB, "integrity check of pluto failed");
		return FALSE;
	}
	return TRUE;
}

