/*
 * Copyright (C) 2013 Andreas Steffen
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

#include "imv_session.h"

#include <utils/debug.h>

typedef struct private_imv_session_t private_imv_session_t;

/**
 * Private data of a imv_session_t object.
 */
struct private_imv_session_t {

	/**
	 * Public imv_session_t interface.
	 */
	imv_session_t public;

	/**
	 * Unique Session ID
	 */
	int session_id;

	/**
	 * TNCCS connection ID
	 */
	TNC_ConnectionID conn_id;

	/**
	 * Have the workitems been generated?
	 */
	bool policy_started;

	/**
	 * List of worklist items
	 */
	linked_list_t *workitems;

	/**
	 * Reference count
	 */
	refcount_t ref;

};

METHOD(imv_session_t, get_session_id, int,
	private_imv_session_t *this)
{
	return this->session_id;
}

METHOD(imv_session_t, get_connection_id, TNC_ConnectionID,
	private_imv_session_t *this)
{
	return this->conn_id;
}

METHOD(imv_session_t, set_policy_started, void,
	private_imv_session_t *this, bool start)
{
	this->policy_started = start;
}

METHOD(imv_session_t, get_policy_started, bool,
	private_imv_session_t *this)
{
	return this->policy_started;
}

METHOD(imv_session_t, insert_workitem, void,
	private_imv_session_t *this, imv_workitem_t *workitem)
{
	this->workitems->insert_last(this->workitems, workitem);
}

METHOD(imv_session_t, remove_workitem, void,
	private_imv_session_t *this, enumerator_t *enumerator)
{
	this->workitems->remove_at(this->workitems, enumerator);
}

METHOD(imv_session_t, create_workitem_enumerator, enumerator_t*,
	private_imv_session_t *this)
{
	if (!this->policy_started)
	{
		return NULL;
	}
	return this->workitems->create_enumerator(this->workitems);
}

METHOD(imv_session_t, get_workitem_count, int,
	private_imv_session_t *this, TNC_IMVID imv_id)
{
	enumerator_t *enumerator;
	imv_workitem_t *workitem;
	int count = 0;

	enumerator = this->workitems->create_enumerator(this->workitems);
	while (enumerator->enumerate(enumerator, &workitem))
	{
		if (workitem->get_imv_id(workitem) == imv_id)
		{
			count++;
		}
	}
	enumerator->destroy(enumerator);

	return count;
}

METHOD(imv_session_t, get_ref, imv_session_t*,
	private_imv_session_t *this)
{
	ref_get(&this->ref);

	return &this->public;
}

METHOD(imv_session_t, destroy, void,
	private_imv_session_t *this)
{
	if (ref_put(&this->ref))
	{
		this->workitems->destroy_offset(this->workitems,
								 offsetof(imv_workitem_t, destroy));
		free(this);
	}
}

/**
 * See header
 */
imv_session_t *imv_session_create(int session_id, TNC_ConnectionID conn_id)
{
	private_imv_session_t *this;

	INIT(this,
		.public = {
			.get_session_id = _get_session_id,
			.get_connection_id = _get_connection_id,
			.set_policy_started = _set_policy_started,
			.get_policy_started = _get_policy_started,
			.insert_workitem = _insert_workitem,
			.remove_workitem = _remove_workitem,
			.create_workitem_enumerator = _create_workitem_enumerator,
			.get_workitem_count = _get_workitem_count,
			.get_ref = _get_ref,
			.destroy = _destroy,
		},
		.session_id = session_id,
		.conn_id = conn_id,
		.workitems = linked_list_create(),
		.ref = 1,
	);

	return &this->public;
}
