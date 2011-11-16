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

#include "main_mode.h"

#include <string.h>

#include <daemon.h>
#include <crypto/diffie_hellman.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/nonce_payload.h>

typedef struct private_main_mode_t private_main_mode_t;

/**
 * Private members of a main_mode_t task.
 */
struct private_main_mode_t {

	/**
	 * Public methods and task_t interface.
	 */
	main_mode_t public;

	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;

	/**
	 * Are we the initiator?
	 */
	bool initiator;

	/**
	 * IKE config to establish
	 */
	ike_cfg_t *config;

	/**
	 * selected IKE proposal
	 */
	proposal_t *proposal;
};

METHOD(task_t, build_i, status_t,
	private_main_mode_t *this, message_t *message)
{
	/* TODO-IKEv1: initiate mainmode */
	return FAILED;
}

METHOD(task_t, process_r,  status_t,
	private_main_mode_t *this, message_t *message)
{
	this->config = this->ike_sa->get_ike_cfg(this->ike_sa);
	DBG0(DBG_IKE, "%H is initiating a Main Mode", message->get_source(message));
	this->ike_sa->set_state(this->ike_sa, IKE_CONNECTING);

	if (!this->proposal)
	{
		linked_list_t *list;
		sa_payload_t *sa_payload;

		sa_payload = (sa_payload_t*)message->get_payload(message,
												SECURITY_ASSOCIATION_V1);
		if (!sa_payload)
		{
			DBG1(DBG_IKE, "SA payload missing");
			return FAILED;
		}
		list = sa_payload->get_proposals(sa_payload);
		this->proposal = this->config->select_proposal(this->config, list, FALSE);

		if (!this->proposal)
		{
			DBG1(DBG_IKE, "no proposal found");
			return FAILED;
		}
	}
	return NEED_MORE;
}

METHOD(task_t, build_r, status_t,
	private_main_mode_t *this, message_t *message)
{
	sa_payload_t *sa_payload;

	sa_payload = sa_payload_create_from_proposal(SECURITY_ASSOCIATION_V1,
												 this->proposal);
	message->add_payload(message, &sa_payload->payload_interface);
	return NEED_MORE;
}

METHOD(task_t, process_i, status_t,
	private_main_mode_t *this, message_t *message)
{
	/* TODO-IKEv1: process main mode as initiator */
	return FAILED;
}

METHOD(task_t, get_type, task_type_t,
	private_main_mode_t *this)
{
	return MAIN_MODE;
}

METHOD(task_t, migrate, void,
	private_main_mode_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
}

METHOD(task_t, destroy, void,
	private_main_mode_t *this)
{
	DESTROY_IF(this->proposal);
	free(this);
}

/*
 * Described in header.
 */
main_mode_t *main_mode_create(ike_sa_t *ike_sa, bool initiator)
{
	private_main_mode_t *this;

	INIT(this,
		.public = {
			.task = {
				.get_type = _get_type,
				.migrate = _migrate,
				.destroy = _destroy,
			},
		},
		.ike_sa = ike_sa,
		.initiator = initiator,
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
