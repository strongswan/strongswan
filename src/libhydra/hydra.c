/*
 * Copyright (C) 2010 Tobias Brunner
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

#include "hydra.h"

#include <debug.h>

typedef struct private_hydra_t private_hydra_t;

/**
 * Private additions to hydra_t.
 */
struct private_hydra_t {

	/**
	 * Public members of hydra_t.
	 */
	hydra_t public;
};

/**
 * Single instance of hydra_t.
 */
hydra_t *hydra;

/**
 * Described in header.
 */
void libhydra_deinit()
{
	private_hydra_t *this = (private_hydra_t*)hydra;
	this->public.attributes->destroy(this->public.attributes);
	this->public.kernel_interface->destroy(this->public.kernel_interface);
	free((void*)this->public.daemon);
	free(this);
	hydra = NULL;
}

/**
 * Described in header.
 */
bool libhydra_init(const char *daemon)
{
	private_hydra_t *this;

	INIT(this,
		.public = {
			.attributes = attribute_manager_create(),
			.daemon = strdup(daemon ?: "libhydra"),
		},
	);
	hydra = &this->public;

	this->public.kernel_interface = kernel_interface_create();

	if (lib->integrity &&
		!lib->integrity->check(lib->integrity, "libhydra", libhydra_init))
	{
		DBG1(DBG_LIB, "integrity check of libhydra failed");
		return FALSE;
	}
	return TRUE;
}

