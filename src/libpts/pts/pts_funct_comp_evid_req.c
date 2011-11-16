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

#include "pts_funct_comp_evid_req.h"

#include <utils/linked_list.h>
#include <debug.h>

typedef struct private_pts_funct_comp_evid_req_t private_pts_funct_comp_evid_req_t;

/**
 * Private data of a private_pts_funct_comp_evid_req_t object.
 *
 */
struct private_pts_funct_comp_evid_req_t {

	/**
	 * Public pts_funct_comp_evid_req_t interface.
	 */
	pts_funct_comp_evid_req_t public;

	/**
	 * List of Functional Component Evidence Requests
	 */
	linked_list_t *list;
};

METHOD(pts_funct_comp_evid_req_t, get_req_count, int,
	private_pts_funct_comp_evid_req_t *this)
{
	return this->list->get_count(this->list);
}

METHOD(pts_funct_comp_evid_req_t, add, void,
		private_pts_funct_comp_evid_req_t *this,
		funct_comp_evid_req_entry_t *entry)
{
	this->list->insert_last(this->list, entry);
}

METHOD(pts_funct_comp_evid_req_t, create_enumerator, enumerator_t*,
	private_pts_funct_comp_evid_req_t *this)
{
	return this->list->create_enumerator(this->list);
}

METHOD(pts_funct_comp_evid_req_t, destroy, void,
	private_pts_funct_comp_evid_req_t *this)
{
	this->list->destroy(this->list);
	free(this);
}

/**
 * See header
 */
pts_funct_comp_evid_req_t *pts_funct_comp_evid_req_create()
{
	private_pts_funct_comp_evid_req_t *this;

	INIT(this,
		.public = {
			.get_req_count = _get_req_count,
			.add = _add,
			.create_enumerator = _create_enumerator,
			.destroy = _destroy,
		},
		.list = linked_list_create(),
	);

	return &this->public;
}

