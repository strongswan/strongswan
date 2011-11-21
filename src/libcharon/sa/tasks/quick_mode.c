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
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/id_payload.h>

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
		QM_NEGOTIATED,
	} state;
};

METHOD(task_t, build_i, status_t,
	private_quick_mode_t *this, message_t *message)
{
	switch (this->state)
	{
		case QM_INIT:
		{
			sa_payload_t *sa_payload;
			nonce_payload_t *nonce_payload;
			id_payload_t *id_payload;
			traffic_selector_t *ts;
			linked_list_t *list;
			rng_t *rng;

			list = this->config->get_proposals(this->config, TRUE);
			sa_payload = sa_payload_create_from_proposal_list(
												SECURITY_ASSOCIATION_V1, list);
			list->destroy_offset(list, offsetof(proposal_t, destroy));
			message->add_payload(message, &sa_payload->payload_interface);

			rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
			if (!rng)
			{
				DBG1(DBG_IKE, "no RNG found to create nonce");
				return FAILED;
			}
			rng->allocate_bytes(rng, NONCE_SIZE, &this->nonce_i);
			rng->destroy(rng);
			nonce_payload = nonce_payload_create(NONCE_V1);
			nonce_payload->set_nonce(nonce_payload, this->nonce_i);
			message->add_payload(message, &nonce_payload->payload_interface);

			list = this->config->get_traffic_selectors(this->config, TRUE, NULL,
									this->ike_sa->get_my_host(this->ike_sa));
			if (list->get_first(list, (void**)&ts) != SUCCESS)
			{
				list->destroy_offset(list, offsetof(traffic_selector_t, destroy));
				DBG1(DBG_IKE, "traffic selector missing");
				return FAILED;
			}
			id_payload = id_payload_create_from_ts(ts);
			this->tsi = ts->clone(ts);
			list->destroy_offset(list, offsetof(traffic_selector_t, destroy));
			message->add_payload(message, &id_payload->payload_interface);

			list = this->config->get_traffic_selectors(this->config, FALSE, NULL,
									this->ike_sa->get_other_host(this->ike_sa));
			if (list->get_first(list, (void**)&ts) != SUCCESS)
			{
				list->destroy_offset(list, offsetof(traffic_selector_t, destroy));
				DBG1(DBG_IKE, "traffic selector missing");
				return FAILED;
			}
			id_payload = id_payload_create_from_ts(ts);
			this->tsr = ts->clone(ts);
			list->destroy_offset(list, offsetof(traffic_selector_t, destroy));
			message->add_payload(message, &id_payload->payload_interface);

			/* TODO-IKEv1: Add HASH(1) */

			return NEED_MORE;
		}
		case QM_NEGOTIATED:
		{
			/* TODO-IKEv1: Send HASH(3) */
			return SUCCESS;
		}
		default:
			return FAILED;
	}
}

METHOD(task_t, process_r, status_t,
	private_quick_mode_t *this, message_t *message)
{
	switch (this->state)
	{
		case QM_INIT:
		{
			sa_payload_t *sa_payload;
			nonce_payload_t *nonce_payload;
			id_payload_t *id_payload;
			payload_t *payload;
			linked_list_t *tsi, *tsr, *list;
			peer_cfg_t *peer_cfg;
			host_t *me, *other;
			enumerator_t *enumerator;
			bool first = TRUE;

			enumerator = message->create_payload_enumerator(message);
			while (enumerator->enumerate(enumerator, &payload))
			{
				if (payload->get_type(payload) == ID_V1)
				{
					id_payload = (id_payload_t*)payload;

					if (first)
					{
						this->tsi = id_payload->get_ts(id_payload);
						first = FALSE;
					}
					else
					{
						this->tsr = id_payload->get_ts(id_payload);
						break;
					}
				}
			}
			enumerator->destroy(enumerator);

			/* TODO-IKEv1: create host2host TS if ID payloads missing */

			me = this->ike_sa->get_virtual_ip(this->ike_sa, TRUE);
			if (!me)
			{
				me = this->ike_sa->get_my_host(this->ike_sa);
			}
			other = this->ike_sa->get_virtual_ip(this->ike_sa, FALSE);
			if (!other)
			{
				other = this->ike_sa->get_other_host(this->ike_sa);
			}
			peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);
			tsi = linked_list_create();
			tsr = linked_list_create();
			tsi->insert_last(tsi, this->tsi);
			tsr->insert_last(tsr, this->tsr);
			this->config = peer_cfg->select_child_cfg(peer_cfg, tsr, tsi,
													  me, other);
			tsi->destroy(tsi);
			tsr->destroy(tsr);
			if (!this->config)
			{
				DBG1(DBG_IKE, "no child config found");
				return FAILED;
			}

			sa_payload = (sa_payload_t*)message->get_payload(message,
													SECURITY_ASSOCIATION_V1);
			if (!sa_payload)
			{
				DBG1(DBG_IKE, "sa payload missing");
				return FAILED;
			}
			list = sa_payload->get_proposals(sa_payload);
			this->proposal = this->config->select_proposal(this->config,
														   list, TRUE, FALSE);
			list->destroy_offset(list, offsetof(proposal_t, destroy));
			if (!this->proposal)
			{
				DBG1(DBG_IKE, "no matching proposal found");
				return FAILED;
			}

			nonce_payload = (nonce_payload_t*)message->get_payload(message,
																   NONCE_V1);
			if (!nonce_payload)
			{
				DBG1(DBG_IKE, "Nonce payload missing");
				return FAILED;
			}
			this->nonce_i = nonce_payload->get_nonce(nonce_payload);

			/* TODO-IKEv1: verify HASH(1) */

			return NEED_MORE;
		}
		case QM_NEGOTIATED:
		{
			/* TODO-IKEv1: verify HASH(3) */

			return SUCCESS;
		}
		default:
			return FAILED;
	}
}

METHOD(task_t, build_r, status_t,
	private_quick_mode_t *this, message_t *message)
{
	switch (this->state)
	{
		case QM_INIT:
		{
			sa_payload_t *sa_payload;
			nonce_payload_t *nonce_payload;
			id_payload_t *id_payload;
			rng_t *rng;

			sa_payload = sa_payload_create_from_proposal(
									SECURITY_ASSOCIATION_V1, this->proposal);
			message->add_payload(message, &sa_payload->payload_interface);

			rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
			if (!rng)
			{
				DBG1(DBG_IKE, "no RNG found to create nonce");
				return FAILED;
			}
			rng->allocate_bytes(rng, NONCE_SIZE, &this->nonce_r);
			rng->destroy(rng);
			nonce_payload = nonce_payload_create(NONCE_V1);
			nonce_payload->set_nonce(nonce_payload, this->nonce_r);
			message->add_payload(message, &nonce_payload->payload_interface);

			id_payload = id_payload_create_from_ts(this->tsi);
			message->add_payload(message, &id_payload->payload_interface);
			id_payload = id_payload_create_from_ts(this->tsr);
			message->add_payload(message, &id_payload->payload_interface);

			/* TODO-IKEv1: add HASH(2) */

			this->state = QM_NEGOTIATED;
			return NEED_MORE;
		}
		default:
			return FAILED;
	}
}

METHOD(task_t, process_i, status_t,
	private_quick_mode_t *this, message_t *message)
{
	switch (this->state)
	{
		case QM_INIT:
		{
			sa_payload_t *sa_payload;
			nonce_payload_t *nonce_payload;
			id_payload_t *id_payload;
			payload_t *payload;
			traffic_selector_t *tsi = NULL, *tsr = NULL;
			linked_list_t *list;
			enumerator_t *enumerator;
			bool first = TRUE;

			enumerator = message->create_payload_enumerator(message);
			while (enumerator->enumerate(enumerator, &payload))
			{
				if (payload->get_type(payload) == ID_V1)
				{
					id_payload = (id_payload_t*)payload;

					if (first)
					{
						tsi = id_payload->get_ts(id_payload);
						first = FALSE;
					}
					else
					{
						tsr = id_payload->get_ts(id_payload);
						break;
					}
				}
			}
			enumerator->destroy(enumerator);

			/* TODO-IKEv1: create host2host TS if ID payloads missing */

			if (!tsr->is_contained_in(tsr, this->tsr) ||
				!tsi->is_contained_in(tsi, this->tsi))
			{
				tsi->destroy(tsi);
				tsr->destroy(tsr);
				DBG1(DBG_IKE, "TS mismatch");
				return FAILED;
			}
			this->tsi->destroy(this->tsi);
			this->tsr->destroy(this->tsr);
			this->tsi = tsi;
			this->tsr = tsr;

			sa_payload = (sa_payload_t*)message->get_payload(message,
													SECURITY_ASSOCIATION_V1);
			if (!sa_payload)
			{
				DBG1(DBG_IKE, "sa payload missing");
				return FAILED;
			}
			list = sa_payload->get_proposals(sa_payload);
			this->proposal = this->config->select_proposal(this->config,
														   list, TRUE, FALSE);
			list->destroy_offset(list, offsetof(proposal_t, destroy));
			if (!this->proposal)
			{
				DBG1(DBG_IKE, "no matching proposal found");
				return FAILED;
			}
			nonce_payload = (nonce_payload_t*)message->get_payload(message,
																   NONCE_V1);
			if (!nonce_payload)
			{
				DBG1(DBG_IKE, "Nonce payload missing");
				return FAILED;
			}
			this->nonce_r = nonce_payload->get_nonce(nonce_payload);

			/* TODO-IKEv1: verify HASH(2) */

			this->state = QM_NEGOTIATED;
			return NEED_MORE;
		}
		default:
			return FAILED;
	}
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
