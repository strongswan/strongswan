/*
 * Copyright (C) 2011 Andreas Steffen
 *
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

#include "ita_comp_tboot.h"
#include "ita_comp_func_name.h"

#include "pts/pts_func_comp_evid_req.h"
#include "pts/components/pts_component.h"

#include <debug.h>
#include <pen/pen.h>

typedef struct pts_ita_comp_tboot_t pts_ita_comp_tboot_t;

/**
 * Private data of a pts_ita_comp_tboot_t object.
 *
 */
struct pts_ita_comp_tboot_t {

	/**
	 * Public pts_component_manager_t interface.
	 */
	pts_component_t public;

	/**
	 * Component Functional Name
	 */
	pts_comp_func_name_t *name;
};

METHOD(pts_component_t, get_comp_func_name, pts_comp_func_name_t*,
	pts_ita_comp_tboot_t *this)
{
	return this->name;
}

METHOD(pts_component_t, get_evidence_flags, u_int8_t,
	pts_ita_comp_tboot_t *this)
{
	return PTS_REQ_FUNC_COMP_FLAG_PCR;
}

METHOD(pts_component_t, measure, bool,
	pts_ita_comp_tboot_t *this)
{
	/* TODO measure the tboot functional component */
	return FALSE;
}

METHOD(pts_component_t, verify, bool,
	pts_ita_comp_tboot_t *this)
{
	/* TODO verify the measurement of the tboot functional component */
	return FALSE;
}

METHOD(pts_component_t, destroy, void,
	pts_ita_comp_tboot_t *this)
{
	this->name->destroy(this->name);
	free(this);
}

/**
 * See header
 */
pts_component_t *pts_ita_comp_tboot_create(u_int8_t qualifier)
{
	pts_ita_comp_tboot_t *this;

	INIT(this,
		.public = {
			.get_comp_func_name = _get_comp_func_name,
			.get_evidence_flags = _get_evidence_flags,
			.measure = _measure,
			.verify = _verify,
			.destroy = _destroy,
		},
		.name = pts_comp_func_name_create(PEN_ITA, PTS_ITA_COMP_FUNC_NAME_TBOOT,
										  qualifier),
	);

	return &this->public;
}

