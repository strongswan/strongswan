/*
 * Copyright (C) 2011 Martin Willi
 * Copyright (C) 2011 revosec AG
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

#include "xauth.h"

#include <daemon.h>
#include <hydra.h>
#include <encoding/payloads/cp_payload.h>

typedef struct private_xauth_t private_xauth_t;

/**
 * Private members of a xauth_t task.
 */
struct private_xauth_t {

	/**
	 * Public methods and task_t interface.
	 */
	xauth_t public;

	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;

	/**
	 * Are we the XAUTH initiator?
	 */
	bool initiator;
};

METHOD(task_t, build_i, status_t,
	private_xauth_t *this, message_t *message)
{
	return FAILED;
}

METHOD(task_t, process_r, status_t,
	private_xauth_t *this, message_t *message)
{
	return FAILED;
}

METHOD(task_t, build_r, status_t,
	private_xauth_t *this, message_t *message)
{
	return FAILED;
}

METHOD(task_t, process_i, status_t,
	private_xauth_t *this, message_t *message)
{
	return FAILED;
}

METHOD(task_t, get_type, task_type_t,
	private_xauth_t *this)
{
	return TASK_XAUTH;
}

METHOD(task_t, migrate, void,
	private_xauth_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
}

METHOD(task_t, destroy, void,
	private_xauth_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
xauth_t *xauth_create(ike_sa_t *ike_sa, bool initiator)
{
	private_xauth_t *this;

	INIT(this,
		.public = {
			.task = {
				.get_type = _get_type,
				.migrate = _migrate,
				.destroy = _destroy,
			},
		},
		.initiator = initiator,
		.ike_sa = ike_sa,
	);

	if (initiator)
	{
		this->public.task.build = _build_i;
		this->public.task.process = _process_i;
	}
	else
	{
		this->public.task.build = _build_r;
		this->public.task.process = _process_r;
	}
	return &this->public;
}
