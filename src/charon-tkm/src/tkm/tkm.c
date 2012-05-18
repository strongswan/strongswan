/*
 * Copyright (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
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

#include "tkm.h"

typedef struct private_tkm_t private_tkm_t;

/**
 * Private additions to tkm_t.
 */
struct private_tkm_t {

	/**
	 * Public members of tkm_t.
	 */
	tkm_t public;
};

/**
 * Single instance of tkm_t.
 */
tkm_t *tkm = NULL;

/**
 * Described in header.
 */
bool tkm_init()
{
	private_tkm_t *this;

	INIT(this,
		.public = {
			.idmgr = tkm_id_manager_create(),
		},
	);
	tkm = &this->public;

	return TRUE;
}

/**
 * Described in header.
 */
void tkm_deinit()
{
	if (!tkm)
	{
		return;
	}
	private_tkm_t *this = (private_tkm_t*)tkm;
	this->public.idmgr->destroy(this->public.idmgr);
	free(this);
	tkm = NULL;
}
