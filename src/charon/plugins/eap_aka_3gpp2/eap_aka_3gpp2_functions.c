/*
 * Copyright (C) 2008-2009 Martin Willi
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

#include "eap_aka_3gpp2_functions.h"

typedef struct private_eap_aka_3gpp2_functions_t private_eap_aka_3gpp2_functions_t;

/**
 * Private data of an eap_aka_3gpp2_functions_t object.
 */
struct private_eap_aka_3gpp2_functions_t {

	/**
	 * Public eap_aka_3gpp2_functions_t interface.
	 */
	eap_aka_3gpp2_functions_t public;
};

/**
 * Implementation of eap_aka_3gpp2_functions_t.destroy.
 */
static void destroy(private_eap_aka_3gpp2_functions_t *this)
{
	free(this);
}

/**
 * See header
 */
eap_aka_3gpp2_functions_t *eap_aka_3gpp2_functions_create()
{
	private_eap_aka_3gpp2_functions_t *this = malloc_thing(private_eap_aka_3gpp2_functions_t);

	this->public.destroy = (void(*)(eap_aka_3gpp2_functions_t*))destroy;

	return &this->public;
}

