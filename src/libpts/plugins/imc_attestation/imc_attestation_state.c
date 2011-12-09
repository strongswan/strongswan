/*
 * Copyright (C) 2011 Sansar Choinyambuu
 * HSR Hochschule fuer Technik Rapperswil
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

#include "imc_attestation_state.h"

#include <utils/linked_list.h>
#include <debug.h>

typedef struct private_imc_attestation_state_t private_imc_attestation_state_t;

/**
 * Private data of an imc_attestation_state_t object.
 */
struct private_imc_attestation_state_t {

	/**
	 * Public members of imc_attestation_state_t
	 */
	imc_attestation_state_t public;

	/**
	 * TNCCS connection ID
	 */
	TNC_ConnectionID connection_id;

	/**
	 * TNCCS connection state
	 */
	TNC_ConnectionState state;

	/**
	 * Does the TNCCS connection support long message types?
	 */
	bool has_long;

	/**
	 * Does the TNCCS connection support exclusive delivery?
	 */
	bool has_excl;

	/**
	 * PTS object
	 */
	pts_t *pts;

	/**
	 * PTS Component Evidence list
	 */
	linked_list_t *list;

};

METHOD(imc_state_t, get_connection_id, TNC_ConnectionID,
	private_imc_attestation_state_t *this)
{
	return this->connection_id;
}

METHOD(imc_state_t, has_long, bool,
	private_imc_attestation_state_t *this)
{
	return this->has_long;
}

METHOD(imc_state_t, has_excl, bool,
	private_imc_attestation_state_t *this)
{
	return this->has_excl;
}

METHOD(imc_state_t, set_flags, void,
	private_imc_attestation_state_t *this, bool has_long, bool has_excl)
{
	this->has_long = has_long;
	this->has_excl = has_excl;
}

METHOD(imc_state_t, change_state, void,
	private_imc_attestation_state_t *this, TNC_ConnectionState new_state)
{
	this->state = new_state;
}


METHOD(imc_state_t, destroy, void,
	private_imc_attestation_state_t *this)
{
	this->pts->destroy(this->pts);
	this->list->destroy_offset(this->list, offsetof(pts_comp_evidence_t, destroy));
	free(this);
}

METHOD(imc_attestation_state_t, get_pts, pts_t*,
	private_imc_attestation_state_t *this)
{
	return this->pts;
}

METHOD(imc_attestation_state_t, add_evidence, void,
	private_imc_attestation_state_t *this, pts_comp_evidence_t *evidence)
{
	this->list->insert_last(this->list, evidence);
}

METHOD(imc_attestation_state_t, next_evidence, bool,
	private_imc_attestation_state_t *this, pts_comp_evidence_t **evid)
{
	return this->list->remove_first(this->list, (void**)evid) == SUCCESS;
}

/**
 * Described in header.
 */
imc_state_t *imc_attestation_state_create(TNC_ConnectionID connection_id)
{
	private_imc_attestation_state_t *this;
	char *platform_info;

	INIT(this,
		.public = {
			.interface = {
				.get_connection_id = _get_connection_id,
				.has_long = _has_long,
				.has_excl = _has_excl,
				.set_flags = _set_flags,
				.change_state = _change_state,
				.destroy = _destroy,
			},
			.get_pts = _get_pts,
			.add_evidence = _add_evidence,
			.next_evidence = _next_evidence,
		},
		.connection_id = connection_id,
		.state = TNC_CONNECTION_STATE_CREATE,
		.pts = pts_create(TRUE),
		.list = linked_list_create(),
	);

	platform_info = lib->settings->get_str(lib->settings,
						 "libimcv.plugins.imc-attestation.platform_info", NULL);
	if (platform_info)
	{
		this->pts->set_platform_info(this->pts, platform_info);
	}
	
	return &this->public.interface;
}


