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

#include "eap_aka_3gpp2_provider.h"

typedef struct private_eap_aka_3gpp2_provider_t private_eap_aka_3gpp2_provider_t;

/**
 * Private data of an eap_aka_3gpp2_provider_t object.
 */
struct private_eap_aka_3gpp2_provider_t {

	/**
	 * Public eap_aka_3gpp2_provider_t interface.
	 */
	eap_aka_3gpp2_provider_t public;

	/**
	 * AKA functions
	 */
	eap_aka_3gpp2_functions_t *f;
};

/**
 * Implementation of usim_provider_t.get_quintuplet
 */
static bool get_quintuplet(private_eap_aka_3gpp2_provider_t *this,
					identification_t *imsi, char rand[16], char xres[16],
					char ck[16], char ik[16], char autn[16])
{
	return FALSE;
}

/**
 * Implementation of usim_provider_t.resync
 */
static bool resync(private_eap_aka_3gpp2_provider_t *this,
					identification_t *imsi, char rand[16], char auts[16])
{
	return FALSE;
}

/**
 * Implementation of eap_aka_3gpp2_provider_t.destroy.
 */
static void destroy(private_eap_aka_3gpp2_provider_t *this)
{
	free(this);
}

/**
 * See header
 */
eap_aka_3gpp2_provider_t *eap_aka_3gpp2_provider_create(
												eap_aka_3gpp2_functions_t *f)
{
	private_eap_aka_3gpp2_provider_t *this = malloc_thing(private_eap_aka_3gpp2_provider_t);

	this->public.provider.get_quintuplet = (bool(*)(usim_provider_t*, identification_t *imsi, char rand[16], char xres[16], char ck[16], char ik[16], char autn[16]))get_quintuplet;
	this->public.provider.resync = (bool(*)(usim_provider_t*, identification_t *imsi, char rand[16], char auts[16]))resync;
	this->public.destroy = (void(*)(eap_aka_3gpp2_provider_t*))destroy;

	this->f = f;

	return &this->public;
}

