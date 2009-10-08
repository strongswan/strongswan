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

#include "eap_aka_3gpp2_card.h"

#include <daemon.h>

typedef struct private_eap_aka_3gpp2_card_t private_eap_aka_3gpp2_card_t;

/**
 * Private data of an eap_aka_3gpp2_card_t object.
 */
struct private_eap_aka_3gpp2_card_t {

	/**
	 * Public eap_aka_3gpp2_card_t interface.
	 */
	eap_aka_3gpp2_card_t public;

	/**
	 * IMSI, is ID_ANY for this software implementation
	 */
	identification_t *imsi;

	/**
	 * AKA functions
	 */
	eap_aka_3gpp2_functions_t *f;
};

/**
 * Implementation of usim_card_t.get_imsi
 */
static identification_t* get_imsi(private_eap_aka_3gpp2_card_t *this)
{
	return this->imsi;
}

/**
 * Implementation of usim_card_t.get_quintuplet
 */
static status_t get_quintuplet(private_eap_aka_3gpp2_card_t *this,
								char rand[16], char autn[16],
								char ck[16], char ik[16], char res[16])
{
	return FAILED;
}

/**
 * Implementation of usim_card_t.resync
 */
static bool resync(private_eap_aka_3gpp2_card_t *this,
								char rand[16], char auts[16])
{
	return FALSE;
}

/**
 * Implementation of eap_aka_3gpp2_card_t.destroy.
 */
static void destroy(private_eap_aka_3gpp2_card_t *this)
{
	this->imsi->destroy(this->imsi);
	free(this);
}

/**
 * See header
 */
eap_aka_3gpp2_card_t *eap_aka_3gpp2_card_create(eap_aka_3gpp2_functions_t *f)
{
	private_eap_aka_3gpp2_card_t *this = malloc_thing(private_eap_aka_3gpp2_card_t);

	this->public.card.get_imsi = (identification_t*(*)(usim_card_t*))get_imsi;
	this->public.card.get_quintuplet = (status_t(*)(usim_card_t*, char rand[16], char autn[16], char ck[16], char ik[16], char res[16]))get_quintuplet;
	this->public.card.resync = (bool(*)(usim_card_t*, char rand[16], char auts[16]))resync;
	this->public.destroy = (void(*)(eap_aka_3gpp2_card_t*))destroy;

	/* this software USIM can act with all identities */
	this->imsi = identification_create_from_encoding(ID_ANY, chunk_empty);
	this->f = f;

	return &this->public;
}

