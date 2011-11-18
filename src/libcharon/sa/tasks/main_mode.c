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
	ike_cfg_t *ike_cfg;

	/**
	 * selected IKE proposal
	 */
	proposal_t *proposal;

	/**
	 * DH exchange
	 */
	diffie_hellman_t *dh;

	/**
	 * Received public DH value from peer
	 */
	chunk_t dh_value;

	/**
	 * Initiators nonce
	 */
	chunk_t nonce_i;

	/**
	 * Responder nonce
	 */
	chunk_t nonce_r;

	/** states of main mode */
	enum {
		MM_INIT,
		MM_SA,
		MM_KE,
		MM_ID,
	} state;
};

METHOD(task_t, build_i, status_t,
	private_main_mode_t *this, message_t *message)
{
	switch (this->state)
	{
		case MM_INIT:
		{
			sa_payload_t *sa_payload;
			linked_list_t *proposals;

			this->ike_cfg = this->ike_sa->get_ike_cfg(this->ike_sa);
			DBG0(DBG_IKE, "initiating IKE_SA %s[%d] to %H",
				 this->ike_sa->get_name(this->ike_sa),
				 this->ike_sa->get_unique_id(this->ike_sa),
				 this->ike_sa->get_other_host(this->ike_sa));
			this->ike_sa->set_state(this->ike_sa, IKE_CONNECTING);

			proposals = this->ike_cfg->get_proposals(this->ike_cfg);

			sa_payload = sa_payload_create_from_proposal_list(
											SECURITY_ASSOCIATION_V1, proposals);
			proposals->destroy_offset(proposals, offsetof(proposal_t, destroy));

			message->add_payload(message, &sa_payload->payload_interface);

			this->state = MM_SA;
			return NEED_MORE;
		}
		case MM_SA:
		{
			ke_payload_t *ke_payload;
			nonce_payload_t *nonce_payload;
			u_int16_t group;
			rng_t *rng;

			if (!this->proposal->get_algorithm(this->proposal,
										DIFFIE_HELLMAN_GROUP, &group, NULL))
			{
				DBG1(DBG_IKE, "DH group selection failed");
				return FAILED;
			}
			this->dh = lib->crypto->create_dh(lib->crypto, group);
			if (!this->dh)
			{
				DBG1(DBG_IKE, "negotiated DH group not supported");
				return FAILED;
			}
			ke_payload = ke_payload_create_from_diffie_hellman(KEY_EXCHANGE_V1,
															   this->dh);
			message->add_payload(message, &ke_payload->payload_interface);

			rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
			if (!rng)
			{
				DBG1(DBG_IKE, "no RNG found to create nonce");
				return FAILED;
			}
			/* TODO-IKEv1: nonce size? */
			rng->allocate_bytes(rng, 20, &this->nonce_i);
			rng->destroy(rng);

			nonce_payload = nonce_payload_create(NONCE_V1);
			nonce_payload->set_nonce(nonce_payload, this->nonce_i);
			message->add_payload(message, &nonce_payload->payload_interface);

			this->state = MM_KE;
			return NEED_MORE;
		}
		default:
			return FAILED;
	}
}

METHOD(task_t, process_r,  status_t,
	private_main_mode_t *this, message_t *message)
{
	switch (this->state)
	{
		case MM_INIT:
		{

			linked_list_t *list;
			sa_payload_t *sa_payload;

			this->ike_cfg = this->ike_sa->get_ike_cfg(this->ike_sa);
			DBG0(DBG_IKE, "%H is initiating a Main Mode",
				 message->get_source(message));
			this->ike_sa->set_state(this->ike_sa, IKE_CONNECTING);

			sa_payload = (sa_payload_t*)message->get_payload(message,
													SECURITY_ASSOCIATION_V1);
			if (!sa_payload)
			{
				DBG1(DBG_IKE, "SA payload missing");
				return FAILED;
			}
			list = sa_payload->get_proposals(sa_payload);
			this->proposal = this->ike_cfg->select_proposal(this->ike_cfg,
															list, FALSE);
			list->destroy_offset(list, offsetof(proposal_t, destroy));
			if (!this->proposal)
			{
				DBG1(DBG_IKE, "no proposal found");
				return FAILED;
			}
			this->state = MM_SA;
			return NEED_MORE;
		}
		case MM_SA:
		{
			ke_payload_t *ke_payload;
			nonce_payload_t *nonce_payload;
			u_int16_t group;

			ke_payload = (ke_payload_t*)message->get_payload(message,
															 KEY_EXCHANGE_V1);
			if (!ke_payload)
			{
				DBG1(DBG_IKE, "KE payload missing");
				return FAILED;
			}
			this->dh_value = ke_payload->get_key_exchange_data(ke_payload);
			this->dh_value = chunk_clone(this->dh_value);

			if (!this->proposal->get_algorithm(this->proposal,
										DIFFIE_HELLMAN_GROUP, &group, NULL))
			{
				DBG1(DBG_IKE, "DH group selection failed");
				return FAILED;
			}
			this->dh = lib->crypto->create_dh(lib->crypto, group);
			if (!this->dh)
			{
				DBG1(DBG_IKE, "negotiated DH group not supported");
				return FAILED;
			}
			this->dh->set_other_public_value(this->dh, this->dh_value);


			nonce_payload = (nonce_payload_t*)message->get_payload(message,
																   NONCE_V1);
			if (!nonce_payload)
			{
				DBG1(DBG_IKE, "Nonce payload missing");
				return FAILED;
			}
			this->nonce_i = nonce_payload->get_nonce(nonce_payload);
			/* TODO-IKEv1: verify nonce length */

			this->state = MM_KE;
			return NEED_MORE;
		}
		default:
			return FAILED;
	}
}

METHOD(task_t, build_r, status_t,
	private_main_mode_t *this, message_t *message)
{
	switch (this->state)
	{
		case MM_SA:
		{
			sa_payload_t *sa_payload;

			sa_payload = sa_payload_create_from_proposal(SECURITY_ASSOCIATION_V1,
														 this->proposal);
			message->add_payload(message, &sa_payload->payload_interface);
			return NEED_MORE;
		}
		case MM_KE:
		{
			ke_payload_t *ke_payload;
			nonce_payload_t *nonce_payload;
			rng_t *rng;

			ke_payload = ke_payload_create_from_diffie_hellman(KEY_EXCHANGE_V1,
															   this->dh);
			message->add_payload(message, &ke_payload->payload_interface);

			rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
			if (!rng)
			{
				DBG1(DBG_IKE, "no RNG found to create nonce");
				return FAILED;
			}
			/* TODO-IKEv1: nonce size? */
			rng->allocate_bytes(rng, 20, &this->nonce_r);
			rng->destroy(rng);

			nonce_payload = nonce_payload_create(NONCE_V1);
			nonce_payload->set_nonce(nonce_payload, this->nonce_r);
			message->add_payload(message, &nonce_payload->payload_interface);
			return NEED_MORE;
		}
		default:
			return FAILED;
	}
}

METHOD(task_t, process_i, status_t,
	private_main_mode_t *this, message_t *message)
{
	switch (this->state)
	{
		case MM_SA:
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
			this->proposal = this->ike_cfg->select_proposal(this->ike_cfg,
															list, FALSE);
			list->destroy_offset(list, offsetof(proposal_t, destroy));
			if (!this->proposal)
			{
				DBG1(DBG_IKE, "no proposal found");
				return FAILED;
			}
			return NEED_MORE;
		}
		case MM_KE:
		{
			ke_payload_t *ke_payload;
			nonce_payload_t *nonce_payload;

			ke_payload = (ke_payload_t*)message->get_payload(message,
															 KEY_EXCHANGE_V1);
			if (!ke_payload)
			{
				DBG1(DBG_IKE, "KE payload missing");
				return FAILED;
			}
			this->dh_value = ke_payload->get_key_exchange_data(ke_payload);
			this->dh_value = chunk_clone(this->dh_value);
			this->dh->set_other_public_value(this->dh, this->dh_value);

			nonce_payload = (nonce_payload_t*)message->get_payload(message,
																   NONCE_V1);
			if (!nonce_payload)
			{
				DBG1(DBG_IKE, "Nonce payload missing");
				return FAILED;
			}
			this->nonce_r = nonce_payload->get_nonce(nonce_payload);
			/* TODO-IKEv1: verify nonce length */

			return NEED_MORE;
		}
		default:
			return FAILED;
	}
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
	DESTROY_IF(this->dh);
	free(this->dh_value.ptr);
	free(this->nonce_i.ptr);
	free(this->nonce_r.ptr);
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
		.state = MM_INIT,
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
