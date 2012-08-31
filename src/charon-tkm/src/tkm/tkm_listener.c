/*
 * Copyrigth (C) 2012 Reto Buerki
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

#include <daemon.h>
#include <tkm/types.h>

#include "tkm_listener.h"
#include "tkm_keymat.h"

typedef struct private_tkm_listener_t private_tkm_listener_t;

/**
 * Private data of a tkm_listener_t object.
 */
struct private_tkm_listener_t {

	/**
	 * Public tkm_listener_t interface.
	 */
	tkm_listener_t public;

};

METHOD(listener_t, authorize, bool,
	private_tkm_listener_t *this, ike_sa_t *ike_sa,
	bool final, bool *success)
{
	if (!final)
	{
		return TRUE;
	}

	tkm_keymat_t * const keymat = (tkm_keymat_t*)ike_sa->get_keymat(ike_sa);
	const isa_id_type isa_id = keymat->get_isa_id(keymat);
	DBG1(DBG_IKE, "TKM authorize listener called for ISA context %llu", isa_id);

	*success = TRUE;
	return TRUE;
}

METHOD(tkm_listener_t, destroy, void,
	private_tkm_listener_t *this)
{
	free(this);
}

/**
 * See header
 */
tkm_listener_t *tkm_listener_create()
{
	private_tkm_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.authorize = _authorize,
			},
			.destroy = _destroy,
		},
	);

	return &this->public;
}
