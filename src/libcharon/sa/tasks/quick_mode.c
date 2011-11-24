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
#include <sa/keymat_v1.h>
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
	 * TRUE if we are initiating quick mode
	 */
	bool initiator;

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
	 * Initiators ESP SPI
	 */
	u_int32_t spi_i;

	/**
	 * Responder ESP SPI
	 */
	u_int32_t spi_r;

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

	/**
	 * IKEv1 keymat
	 */
	keymat_v1_t *keymat;

	/** states of quick mode */
	enum {
		QM_INIT,
		QM_NEGOTIATED,
	} state;
};

/**
 * Install negotiated CHILD_SA
 */
static bool install(private_quick_mode_t *this)
{
	status_t status, status_i, status_o;
	chunk_t encr_i, encr_r, integ_i, integ_r;
	linked_list_t *tsi, *tsr;

	this->child_sa->set_proposal(this->child_sa, this->proposal);
	this->child_sa->set_state(this->child_sa, CHILD_INSTALLING);
	this->child_sa->set_mode(this->child_sa, MODE_TUNNEL);
	this->child_sa->set_protocol(this->child_sa,
								 this->proposal->get_protocol(this->proposal));

	status_i = status_o = FAILED;
	encr_i = encr_r = integ_i = integ_r = chunk_empty;
	tsi = linked_list_create();
	tsr = linked_list_create();
	tsi->insert_last(tsi, this->tsi);
	tsr->insert_last(tsr, this->tsr);
	if (this->keymat->derive_child_keys(this->keymat, this->proposal, NULL,
						this->spi_i, this->spi_r, this->nonce_i, this->nonce_r,
						&encr_i, &integ_i, &encr_r, &integ_r))
	{
		if (this->initiator)
		{
			status_i = this->child_sa->install(this->child_sa, encr_r, integ_r,
							this->spi_i, 0, TRUE, FALSE, tsi, tsr);
			status_o = this->child_sa->install(this->child_sa, encr_i, integ_i,
							this->spi_r, 0, FALSE, FALSE, tsi, tsr);
		}
		else
		{
			status_i = this->child_sa->install(this->child_sa, encr_i, integ_i,
							this->spi_r, 0, TRUE, FALSE, tsr, tsi);
			status_o = this->child_sa->install(this->child_sa, encr_r, integ_r,
							this->spi_i, 0, FALSE, FALSE, tsr, tsi);
		}
	}
	chunk_clear(&integ_i);
	chunk_clear(&integ_r);
	chunk_clear(&encr_i);
	chunk_clear(&encr_r);

	if (status_i != SUCCESS || status_o != SUCCESS)
	{
		DBG1(DBG_IKE, "unable to install %s%s%sIPsec SA (SAD) in kernel",
			(status_i != SUCCESS) ? "inbound " : "",
			(status_i != SUCCESS && status_o != SUCCESS) ? "and ": "",
			(status_o != SUCCESS) ? "outbound " : "");
		tsi->destroy(tsi);
		tsr->destroy(tsr);
		return FALSE;
	}

	if (this->initiator)
	{
		status = this->child_sa->add_policies(this->child_sa, tsi, tsr);
	}
	else
	{
		status = this->child_sa->add_policies(this->child_sa, tsr, tsi);
	}
	tsi->destroy(tsi);
	tsr->destroy(tsr);
	if (status != SUCCESS)
	{
		DBG1(DBG_IKE, "unable to install IPsec policies (SPD) in kernel");
		return FALSE;
	}

	charon->bus->child_keys(charon->bus, this->child_sa, this->initiator,
							NULL, this->nonce_i, this->nonce_r);

	/* add to IKE_SA, and remove from task */
	this->child_sa->set_state(this->child_sa, CHILD_INSTALLED);
	this->ike_sa->add_child_sa(this->ike_sa, this->child_sa);

	DBG0(DBG_IKE, "CHILD_SA %s{%d} established "
		 "with SPIs %.8x_i %.8x_o and TS %#R=== %#R",
		 this->child_sa->get_name(this->child_sa),
		 this->child_sa->get_reqid(this->child_sa),
		 ntohl(this->child_sa->get_spi(this->child_sa, TRUE)),
		 ntohl(this->child_sa->get_spi(this->child_sa, FALSE)),
		 this->child_sa->get_traffic_selectors(this->child_sa, TRUE),
		 this->child_sa->get_traffic_selectors(this->child_sa, FALSE));

	charon->bus->child_updown(charon->bus, this->child_sa, TRUE);

	this->child_sa = NULL;

	return TRUE;
}

/**
 * Generate and add NONCE
 */
static bool add_nonce(private_quick_mode_t *this, chunk_t *nonce,
					  message_t *message)
{
	nonce_payload_t *nonce_payload;
	rng_t *rng;

	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		DBG1(DBG_IKE, "no RNG found to create nonce");
		return FALSE;
	}
	rng->allocate_bytes(rng, NONCE_SIZE, nonce);
	rng->destroy(rng);

	nonce_payload = nonce_payload_create(NONCE_V1);
	nonce_payload->set_nonce(nonce_payload, *nonce);
	message->add_payload(message, &nonce_payload->payload_interface);

	return TRUE;
}

/**
 * Extract nonce from NONCE payload
 */
static bool get_nonce(private_quick_mode_t *this, chunk_t *nonce,
					  message_t *message)
{
	nonce_payload_t *nonce_payload;

	nonce_payload = (nonce_payload_t*)message->get_payload(message, NONCE_V1);
	if (!nonce_payload)
	{
		DBG1(DBG_IKE, "NONCE payload missing in message");
		return FALSE;
	}
	*nonce = nonce_payload->get_nonce(nonce_payload);

	return TRUE;
}

METHOD(task_t, build_i, status_t,
	private_quick_mode_t *this, message_t *message)
{
	switch (this->state)
	{
		case QM_INIT:
		{
			enumerator_t *enumerator;
			sa_payload_t *sa_payload;
			id_payload_t *id_payload;
			traffic_selector_t *ts;
			linked_list_t *list;
			proposal_t *proposal;

			this->child_sa = child_sa_create(
									this->ike_sa->get_my_host(this->ike_sa),
									this->ike_sa->get_other_host(this->ike_sa),
									this->config, 0, FALSE);

			list = this->config->get_proposals(this->config, TRUE);

			this->spi_i = this->child_sa->alloc_spi(this->child_sa, PROTO_ESP);
			if (!this->spi_i)
			{
				DBG1(DBG_IKE, "allocating SPI from kernel failed");
				return FAILED;
			}
			enumerator = list->create_enumerator(list);
			while (enumerator->enumerate(enumerator, &proposal))
			{
				proposal->set_spi(proposal, this->spi_i);
			}
			enumerator->destroy(enumerator);

			sa_payload = sa_payload_create_from_proposal_list(
												SECURITY_ASSOCIATION_V1, list);
			list->destroy_offset(list, offsetof(proposal_t, destroy));
			message->add_payload(message, &sa_payload->payload_interface);

			if (!add_nonce(this, &this->nonce_i, message))
			{
				return FAILED;
			}

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

			return NEED_MORE;
		}
		case QM_NEGOTIATED:
		{
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
			id_payload_t *id_payload;
			payload_t *payload;
			linked_list_t *tsi, *tsr, *list;
			peer_cfg_t *peer_cfg;
			host_t *me, *other, *host;
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

			if (!this->tsi)
			{
				host = this->ike_sa->get_other_host(this->ike_sa);
				this->tsi = traffic_selector_create_from_subnet(host->clone(host),
						host->get_family(host) == AF_INET ? 32 : 128, 0, 0);
			}
			if (!this->tsr)
			{
				host = this->ike_sa->get_my_host(this->ike_sa);
				this->tsr = traffic_selector_create_from_subnet(host->clone(host),
						host->get_family(host) == AF_INET ? 32 : 128, 0, 0);
			}

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
			this->spi_i = this->proposal->get_spi(this->proposal);

			if (!get_nonce(this, &this->nonce_i, message))
			{
				return FAILED;
			}
			this->child_sa = child_sa_create(
									this->ike_sa->get_my_host(this->ike_sa),
									this->ike_sa->get_other_host(this->ike_sa),
									this->config, 0, FALSE);
			return NEED_MORE;
		}
		case QM_NEGOTIATED:
		{
			if (!install(this))
			{
				return FAILED;
			}
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
			id_payload_t *id_payload;

			this->spi_r = this->child_sa->alloc_spi(this->child_sa, PROTO_ESP);
			if (!this->spi_r)
			{
				DBG1(DBG_IKE, "allocating SPI from kernel failed");
				return FAILED;
			}
			this->proposal->set_spi(this->proposal, this->spi_r);

			sa_payload = sa_payload_create_from_proposal(
									SECURITY_ASSOCIATION_V1, this->proposal);
			message->add_payload(message, &sa_payload->payload_interface);

			if (!add_nonce(this, &this->nonce_r, message))
			{
				return FAILED;
			}

			id_payload = id_payload_create_from_ts(this->tsi);
			message->add_payload(message, &id_payload->payload_interface);
			id_payload = id_payload_create_from_ts(this->tsr);
			message->add_payload(message, &id_payload->payload_interface);

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
			id_payload_t *id_payload;
			payload_t *payload;
			traffic_selector_t *tsi = NULL, *tsr = NULL;
			linked_list_t *list;
			enumerator_t *enumerator;
			host_t *host;
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

			if (!tsr)
			{
				host = this->ike_sa->get_other_host(this->ike_sa);
				tsr = traffic_selector_create_from_subnet(host->clone(host),
						host->get_family(host) == AF_INET ? 32 : 128, 0, 0);
			}
			if (!tsi)
			{
				host = this->ike_sa->get_my_host(this->ike_sa);
				tsi = traffic_selector_create_from_subnet(host->clone(host),
						host->get_family(host) == AF_INET ? 32 : 128, 0, 0);
			}

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
			this->spi_r = this->proposal->get_spi(this->proposal);

			if (!get_nonce(this, &this->nonce_r, message))
			{
				return FAILED;
			}
			if (!install(this))
			{
				return FAILED;
			}
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
		.initiator = config != NULL,
		.config = config,
		.keymat = (keymat_v1_t*)ike_sa->get_keymat(ike_sa),
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
