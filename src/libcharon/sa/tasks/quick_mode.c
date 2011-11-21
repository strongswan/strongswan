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

#include "quick_mode.h"

#include <string.h>

#include <daemon.h>

typedef struct private_quick_mode_t private_quick_mode_t;

/**
 * Private members of a quick_mode_t task.
 */
struct private_quick_mode_t {

	/**
	 * Public methods and task_t interface.
	 */
	quick_mode_t public;

	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;

	/**
	 * Traffic selector of initiator
	 */
	traffic_selector_t *tsi;

	/**
	 * Traffic selector of responder
	 */
	traffic_selector_t *tsr;

	/**
	 * Initiators nonce
	 */
	chunk_t nonce_i;

	/**
	 * Responder nonce
	 */
	chunk_t nonce_r;

	/**
	 * selected CHILD_SA proposal
	 */
	proposal_t *proposal;

	/**
	 * Config of CHILD_SA to establish
	 */
	child_cfg_t *config;

	/**
	 * CHILD_SA we are about to establish
	 */
	child_sa_t *child_sa;

	/** states of quick mode */
	enum {
		QM_INIT,
	} state;
};

METHOD(task_t, build_i, status_t,
	private_quick_mode_t *this, message_t *message)
{
	return NEED_MORE;
}

METHOD(task_t, process_r, status_t,
	private_quick_mode_t *this, message_t *message)
{
	return NEED_MORE;
}

METHOD(task_t, build_r, status_t,
	private_quick_mode_t *this, message_t *message)
{
	return SUCCESS;
}

METHOD(task_t, process_i, status_t,
	private_quick_mode_t *this, message_t *message)
{
	return SUCCESS;
}

METHOD(task_t, get_type, task_type_t,
	private_quick_mode_t *this)
{
	return TASK_QUICK_MODE;
}

METHOD(task_t, migrate, void,
	private_quick_mode_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
}

METHOD(task_t, destroy, void,
	private_quick_mode_t *this)
{
	chunk_free(&this->nonce_i);
	chunk_free(&this->nonce_r);
	DESTROY_IF(this->tsi);
	DESTROY_IF(this->tsr);
	DESTROY_IF(this->proposal);
	DESTROY_IF(this->child_sa);
	DESTROY_IF(this->config);
	free(this);
}

/*
 * Described in header.
 */
quick_mode_t *quick_mode_create(ike_sa_t *ike_sa, child_cfg_t *config,
							traffic_selector_t *tsi, traffic_selector_t *tsr)
{
	private_quick_mode_t *this;

	INIT(this,
		.public = {
			.task = {
				.get_type = _get_type,
				.migrate = _migrate,
				.destroy = _destroy,
			},
		},
		.ike_sa = ike_sa,
		.tsi = tsi ? tsi->clone(tsi) : NULL,
		.tsr = tsr ? tsr->clone(tsr) : NULL,
		.config = config,
		.state = QM_INIT,
	);

	if (config)
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
