/*
 * Copyright (C) 2008 Tobias Brunner
 * Copyright (C) 2005-2007 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 * Hochschule fuer Technik Rapperswil
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
 *
 * $Id$
 */

#include "child_create.h"

#include <daemon.h>
#include <crypto/diffie_hellman.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/ts_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <processing/jobs/delete_ike_sa_job.h>


typedef struct private_child_create_t private_child_create_t;

/**
 * Private members of a child_create_t task.
 */
struct private_child_create_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	child_create_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Are we the initiator?
	 */
	bool initiator;
	
	/**
	 * nonce chosen by us
	 */
	chunk_t my_nonce;
	
	/**
	 * nonce chosen by peer
	 */
	chunk_t other_nonce;
	
	/**
	 * config to create the CHILD_SA from
	 */
	child_cfg_t *config;
	
	/**
	 * list of proposal candidates
	 */
	linked_list_t *proposals;
	
	/**
	 * selected proposal to use for CHILD_SA
	 */
	proposal_t *proposal;
	
	/**
	 * traffic selectors for initiators side
	 */
	linked_list_t *tsi;
	
	/**
	 * traffic selectors for responders side
	 */
	linked_list_t *tsr;
	
	/**
	 * optional diffie hellman exchange
	 */
	diffie_hellman_t *dh;
	
	/**
	 * group used for DH exchange
	 */
	diffie_hellman_group_t dh_group;
	
	/**
	 * mode the new CHILD_SA uses (transport/tunnel/beet)
	 */
	mode_t mode;
	
	/**
	 * IPComp transform to use
	 */
	ipcomp_transform_t ipcomp;
	
	/**
	 * IPComp transform proposed or accepted by the other peer
	 */
	ipcomp_transform_t ipcomp_received;
	
	/**
	 * Other Compression Parameter Index (CPI)
	 */
	u_int16_t other_cpi;
	
	/**
	 * reqid to use if we are rekeying
	 */
	u_int32_t reqid;
	
	/**
	 * CHILD_SA which gets established
	 */
	child_sa_t *child_sa;
	
	/**
	 * successfully established the CHILD?
	 */
	bool established;
};

/**
 * get the nonce from a message
 */
static status_t get_nonce(message_t *message, chunk_t *nonce)
{
	nonce_payload_t *payload;
	
	payload = (nonce_payload_t*)message->get_payload(message, NONCE);
	if (payload == NULL)
	{
		return FAILED;
	}
	*nonce = payload->get_nonce(payload);
	return NEED_MORE;
}

/**
 * generate a new nonce to include in a CREATE_CHILD_SA message
 */
static status_t generate_nonce(chunk_t *nonce)
{
	rng_t *rng;
	
	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		DBG1(DBG_IKE, "error generating nonce value, no RNG found");
		return FAILED;
	}
	rng->allocate_bytes(rng, NONCE_SIZE, nonce);
	rng->destroy(rng);
	return SUCCESS;
}

/**
 * Check a list of traffic selectors if any selector belongs to host
 */
static bool ts_list_is_host(linked_list_t *list, host_t *host)
{
	traffic_selector_t *ts;
	bool is_host = TRUE;
	iterator_t *iterator = list->create_iterator(list, TRUE);
	
	while (is_host && iterator->iterate(iterator, (void**)&ts))
	{
		is_host = is_host && ts->is_host(ts, host);
	}
	iterator->destroy(iterator);
	return is_host;
}

/**
 * Install a CHILD_SA for usage, return value:
 * - FAILED: no acceptable proposal
 * - INVALID_ARG: diffie hellman group inacceptable
 * - NOT_FOUND: TS inacceptable
 */
static status_t select_and_install(private_child_create_t *this, bool no_dh)
{
	prf_plus_t *prf_plus;
	status_t status;
	chunk_t nonce_i, nonce_r, secret, seed;
	linked_list_t *my_ts, *other_ts;
	host_t *me, *other, *other_vip, *my_vip;
	
	if (this->proposals == NULL)
	{
		SIG(CHILD_UP_FAILED, "SA payload missing in message");
		return FAILED;
	}
	if (this->tsi == NULL || this->tsr == NULL)
	{
		SIG(CHILD_UP_FAILED, "TS payloads missing in message");
		return NOT_FOUND;
	}
	
	if (this->initiator)
	{
		nonce_i = this->my_nonce;
		nonce_r = this->other_nonce;
		my_ts = this->tsi;
		other_ts = this->tsr;
	}
	else
	{
		nonce_r = this->my_nonce;
		nonce_i = this->other_nonce;
		my_ts = this->tsr;
		other_ts = this->tsi;
	}
	
	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	my_vip = this->ike_sa->get_virtual_ip(this->ike_sa, TRUE);
	other_vip = this->ike_sa->get_virtual_ip(this->ike_sa, FALSE);

	this->proposal = this->config->select_proposal(this->config, this->proposals,
												   no_dh);
	if (this->proposal == NULL)
	{
		SIG(CHILD_UP_FAILED, "no acceptable proposal found");
		return FAILED;
	}
	
	if (!this->proposal->has_dh_group(this->proposal, this->dh_group))
	{
		u_int16_t group;
		
		if (this->proposal->get_algorithm(this->proposal, DIFFIE_HELLMAN_GROUP,
										  &group, NULL))
		{
			SIG(CHILD_UP_FAILED, "DH group %N inacceptable, requesting %N",
				diffie_hellman_group_names, this->dh_group,
				diffie_hellman_group_names, group);
			this->dh_group = group;
			return INVALID_ARG;
		}
		else
		{
			SIG(CHILD_UP_FAILED, "no acceptable proposal found");
			return FAILED;
		}
	}
	
	if (my_vip == NULL)
	{
		my_vip = me;
	}
	else if (this->initiator)
	{
		/* to setup firewall rules correctly, CHILD_SA needs the virtual IP */
		this->child_sa->set_virtual_ip(this->child_sa, my_vip);
	}
	if (other_vip == NULL)
	{
		other_vip = other;
	}
	
	my_ts = this->config->get_traffic_selectors(this->config, TRUE, my_ts,
												my_vip);
	other_ts = this->config->get_traffic_selectors(this->config, FALSE, other_ts, 
												   other_vip);
	
	if (my_ts->get_count(my_ts) == 0 || other_ts->get_count(other_ts) == 0)
	{
		my_ts->destroy_offset(my_ts, offsetof(traffic_selector_t, destroy));
		other_ts->destroy_offset(other_ts, offsetof(traffic_selector_t, destroy));
		SIG(CHILD_UP_FAILED, "no acceptable traffic selectors found");
		return NOT_FOUND;
	}
	
	this->tsr->destroy_offset(this->tsr, offsetof(traffic_selector_t, destroy));
	this->tsi->destroy_offset(this->tsi, offsetof(traffic_selector_t, destroy));
	if (this->initiator)
	{
		this->tsi = my_ts;
		this->tsr = other_ts;
	}
	else
	{
		this->tsr = my_ts;
		this->tsi = other_ts;
	}
	
	if (!this->initiator)
	{
		/* check if requested mode is acceptable, downgrade if required */
		switch (this->mode)
		{
			case MODE_TRANSPORT:
				if (!ts_list_is_host(this->tsi, other) ||
					!ts_list_is_host(this->tsr, me))
				{
					this->mode = MODE_TUNNEL;
					DBG1(DBG_IKE, "not using tranport mode, not host-to-host");
				}
				else if (this->ike_sa->has_condition(this->ike_sa, COND_NAT_ANY))
				{
					this->mode = MODE_TUNNEL;
					DBG1(DBG_IKE, "not using tranport mode, connection NATed");
				}
				break;
			case MODE_BEET:
				if (!ts_list_is_host(this->tsi, NULL) ||
					!ts_list_is_host(this->tsr, NULL))
				{
					this->mode = MODE_TUNNEL;
					DBG1(DBG_IKE, "not using BEET mode, not host-to-host");
				}
				break;
			default:
				break;
		}
	}
	
	if (this->dh)
	{
		if (this->dh->get_shared_secret(this->dh, &secret) != SUCCESS)
		{
			SIG(CHILD_UP_FAILED, "DH exchange incomplete");
			return FAILED;
		}
		DBG3(DBG_IKE, "DH secret %B", &secret);
		seed = chunk_cata("mcc", secret, nonce_i, nonce_r);
	}
	else
	{
		seed = chunk_cata("cc", nonce_i, nonce_r);
	}
	
	if (this->ipcomp != IPCOMP_NONE)
	{
		this->child_sa->activate_ipcomp(this->child_sa, this->ipcomp,
										this->other_cpi);
	}
	
	status = this->child_sa->add_policies(this->child_sa, my_ts, other_ts,
					this->mode, this->proposal->get_protocol(this->proposal));
	if (status != SUCCESS)
	{	
		SIG(CHILD_UP_FAILED, "unable to install IPsec policies (SPD) in kernel");
		return NOT_FOUND;
	}
	
	prf_plus = prf_plus_create(this->ike_sa->get_child_prf(this->ike_sa), seed);
	if (this->initiator)
	{
		status = this->child_sa->update(this->child_sa, this->proposal,
										this->mode, prf_plus);
	}
	else
	{
		status = this->child_sa->add(this->child_sa, this->proposal,
									 this->mode, prf_plus);
	}
	prf_plus->destroy(prf_plus);
	
	if (status != SUCCESS)
	{
		SIG(CHILD_UP_FAILED, "unable to install IPsec SA (SAD) in kernel");
		return FAILED;
	}
	/* add to IKE_SA, and remove from task */
	this->child_sa->set_state(this->child_sa, CHILD_INSTALLED);
	this->ike_sa->add_child_sa(this->ike_sa, this->child_sa);
	this->established = TRUE;
	return SUCCESS;
}

/**
 * build the payloads for the message
 */
static void build_payloads(private_child_create_t *this, message_t *message)
{
	sa_payload_t *sa_payload;
	nonce_payload_t *nonce_payload;
	ke_payload_t *ke_payload;
	ts_payload_t *ts_payload;

	/* add SA payload */
	if (this->initiator)
	{
		sa_payload = sa_payload_create_from_proposal_list(this->proposals);
	}
	else
	{
		sa_payload = sa_payload_create_from_proposal(this->proposal);
	}
	message->add_payload(message, (payload_t*)sa_payload);
	
	/* add nonce payload if not in IKE_AUTH */
	if (message->get_exchange_type(message) == CREATE_CHILD_SA)
	{
		nonce_payload = nonce_payload_create();
		nonce_payload->set_nonce(nonce_payload, this->my_nonce);
		message->add_payload(message, (payload_t*)nonce_payload);
	}
	
	/* diffie hellman exchange, if PFS enabled */
	if (this->dh)
	{
		ke_payload = ke_payload_create_from_diffie_hellman(this->dh);
		message->add_payload(message, (payload_t*)ke_payload);
	}
	
	/* add TSi/TSr payloads */
	ts_payload = ts_payload_create_from_traffic_selectors(TRUE, this->tsi);
	message->add_payload(message, (payload_t*)ts_payload);
	ts_payload = ts_payload_create_from_traffic_selectors(FALSE, this->tsr);
	message->add_payload(message, (payload_t*)ts_payload);

	/* add a notify if we are not in tunnel mode */
	switch (this->mode)
	{
		case MODE_TRANSPORT:
			message->add_notify(message, FALSE, USE_TRANSPORT_MODE, chunk_empty);
			break;
		case MODE_BEET:
			message->add_notify(message, FALSE, USE_BEET_MODE, chunk_empty);
			break;
		default:
			break;
	}
}

/**
 * Adds an IPCOMP_SUPPORTED notify to the message, if possible
 */
static void build_ipcomp_supported_notify(private_child_create_t *this,
										  message_t *message)
{
	u_int16_t cpi;
	u_int8_t tid;

	if (this->ike_sa->has_condition(this->ike_sa, COND_NAT_ANY))
	{
		DBG1(DBG_IKE, "IPComp is not supported if either peer is natted, "
			 "IPComp disabled");
		this->ipcomp = IPCOMP_NONE;
		return;
	}
	
	cpi = this->child_sa->get_my_cpi(this->child_sa);
	tid = this->ipcomp;
	if (cpi)
	{
		message->add_notify(message, FALSE, IPCOMP_SUPPORTED,
				chunk_cata("cc", chunk_from_thing(cpi), chunk_from_thing(tid)));
	}
	else
	{
		DBG1(DBG_IKE, "unable to allocate a CPI from kernel, IPComp disabled");
		this->ipcomp = IPCOMP_NONE;
	}
}

/**
 * Read payloads from message
 */
static void process_payloads(private_child_create_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;
	sa_payload_t *sa_payload;
	ke_payload_t *ke_payload;
	ts_payload_t *ts_payload;
	notify_payload_t *notify_payload;
	
	/* defaults to TUNNEL mode */
	this->mode = MODE_TUNNEL;

	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		switch (payload->get_type(payload))
		{
			case SECURITY_ASSOCIATION:
				sa_payload = (sa_payload_t*)payload;
				this->proposals = sa_payload->get_proposals(sa_payload);
				break;
			case KEY_EXCHANGE:
				ke_payload = (ke_payload_t*)payload;
				if (!this->initiator)
				{
					this->dh_group = ke_payload->get_dh_group_number(ke_payload);
					this->dh = lib->crypto->create_dh(lib->crypto, this->dh_group);
				}
				if (this->dh)
				{
					this->dh->set_other_public_value(this->dh,
								ke_payload->get_key_exchange_data(ke_payload));
				}
				break;
			case TRAFFIC_SELECTOR_INITIATOR:
				ts_payload = (ts_payload_t*)payload;
				this->tsi = ts_payload->get_traffic_selectors(ts_payload);
				break;	
			case TRAFFIC_SELECTOR_RESPONDER:
				ts_payload = (ts_payload_t*)payload;
				this->tsr = ts_payload->get_traffic_selectors(ts_payload);
				break;
			case NOTIFY:
				notify_payload = (notify_payload_t*)payload;
				switch (notify_payload ->get_notify_type(notify_payload ))
				{
					case USE_TRANSPORT_MODE:
						this->mode = MODE_TRANSPORT;
						break;
					case USE_BEET_MODE:
						this->mode = MODE_BEET;
						break;
					case IPCOMP_SUPPORTED:
					{
						chunk_t data = notify_payload->get_notification_data(notify_payload);
						u_int16_t cpi = *(u_int16_t*)data.ptr;
						ipcomp_transform_t ipcomp = (ipcomp_transform_t)(*(data.ptr + 2));
						switch(ipcomp)
						{
							case IPCOMP_DEFLATE:
								this->other_cpi = cpi;
								this->ipcomp_received = ipcomp;
								break;
							case IPCOMP_LZS:
							case IPCOMP_LZJH:
							default:
								DBG1(DBG_IKE, "received IPCOMP_SUPPORTED notify with a transform"
										" ID we don't support %N", ipcomp_transform_names, ipcomp);
								break;
						}
					}
					default:
						break;
				}
				break;
			default:
				break;
		}
	}
	iterator->destroy(iterator);
}

/**
 * Implementation of task_t.build for initiator
 */
static status_t build_i(private_child_create_t *this, message_t *message)
{
	host_t *me, *other, *vip;
	bool propose_all = FALSE;
	peer_cfg_t *peer_cfg;

	switch (message->get_exchange_type(message))
	{
		case IKE_SA_INIT:
			return get_nonce(message, &this->my_nonce);
		case CREATE_CHILD_SA:
			if (generate_nonce(&this->my_nonce) != SUCCESS)
			{
				message->add_notify(message, FALSE, NO_PROPOSAL_CHOSEN, chunk_empty);
				return SUCCESS;
			}
			if (this->dh_group == MODP_NONE)
			{
				this->dh_group = this->config->get_dh_group(this->config);
			}
			break;
		case IKE_AUTH:
			if (!message->get_payload(message, ID_INITIATOR))
			{
				/* send only in the first request, not in subsequent EAP  */
				return NEED_MORE;
			}
			break;
		default:
			break;
	}
	
	SIG(CHILD_UP_START, "establishing CHILD_SA");
	
	/* reuse virtual IP if we already have one */
	me = this->ike_sa->get_virtual_ip(this->ike_sa, TRUE);
	if (me == NULL)
	{
		me = this->ike_sa->get_my_host(this->ike_sa);
	}
	other = this->ike_sa->get_virtual_ip(this->ike_sa, FALSE);
	if (other == NULL)
	{
		other = this->ike_sa->get_other_host(this->ike_sa);
	}
	
	/* check if we want a virtual IP, but don't have one */
	if (!this->reqid)
	{
		peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);
		vip = peer_cfg->get_virtual_ip(peer_cfg);
		if (vip)
		{
			propose_all = TRUE;
		}
	}
	
	if (propose_all)
	{	/* propose a 0.0.0.0/0 subnet when we use virtual ip */
		this->tsi = this->config->get_traffic_selectors(this->config, TRUE,
														NULL, NULL);
	}
	else
	{	/* but shorten a 0.0.0.0/0 subnet for host2host/we already have a vip */
		this->tsi = this->config->get_traffic_selectors(this->config, TRUE,
														NULL, me);
	}
	this->tsr = this->config->get_traffic_selectors(this->config, FALSE, 
													NULL, other);

	this->proposals = this->config->get_proposals(this->config,
												  this->dh_group == MODP_NONE);
	this->mode = this->config->get_mode(this->config);
	
	this->child_sa = child_sa_create(
			this->ike_sa->get_my_host(this->ike_sa),
			this->ike_sa->get_other_host(this->ike_sa),
			this->ike_sa->get_my_id(this->ike_sa), 
			this->ike_sa->get_other_id(this->ike_sa), this->config, this->reqid,
			this->ike_sa->has_condition(this->ike_sa, COND_NAT_ANY));
	
	if (this->child_sa->alloc(this->child_sa, this->proposals) != SUCCESS)
	{
		SIG(CHILD_UP_FAILED, "unable to allocate SPIs from kernel");
		return FAILED;
	}
	
	if (this->dh_group != MODP_NONE)
	{
		this->dh = lib->crypto->create_dh(lib->crypto, this->dh_group);
	}
	
	if (this->config->use_ipcomp(this->config)) {
		/* IPCOMP_DEFLATE is the only transform we support at the moment */
		this->ipcomp = IPCOMP_DEFLATE;
		build_ipcomp_supported_notify(this, message);
	}
	
	build_payloads(this, message);
	
	this->tsi->destroy_offset(this->tsi, offsetof(traffic_selector_t, destroy));
	this->tsr->destroy_offset(this->tsr, offsetof(traffic_selector_t, destroy));
	this->proposals->destroy_offset(this->proposals, offsetof(proposal_t, destroy));
	this->tsi = NULL;
	this->tsr = NULL;
	this->proposals = NULL;
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_r(private_child_create_t *this, message_t *message)
{
	peer_cfg_t *peer_cfg;

	switch (message->get_exchange_type(message))
	{
		case IKE_SA_INIT:
			return get_nonce(message, &this->other_nonce);
		case CREATE_CHILD_SA:
			get_nonce(message, &this->other_nonce);
			break;
		case IKE_AUTH:
			if (message->get_payload(message, ID_INITIATOR) == NULL)
			{
				/* wait until extensible authentication completed, if used */
				return NEED_MORE;
			}
		default:
			break;
	}

	process_payloads(this, message);
	
	if (this->tsi == NULL || this->tsr == NULL)
	{
		DBG1(DBG_IKE, "TS payload missing in message");
		return NEED_MORE;
	}
		  
	peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);
	if (peer_cfg)
	{
		host_t *me, *other;
		
		me = this->ike_sa->get_virtual_ip(this->ike_sa, TRUE);
		if (me == NULL)
		{
			me = this->ike_sa->get_my_host(this->ike_sa);
		}
		other = this->ike_sa->get_virtual_ip(this->ike_sa, FALSE);
		if (other == NULL)
		{
			other = this->ike_sa->get_other_host(this->ike_sa);
		}
		
		this->config = peer_cfg->select_child_cfg(peer_cfg, this->tsr,
												  this->tsi, me, other);
	}
	return NEED_MORE;
}

/**
 * handle CHILD_SA setup failure
 */
static void handle_child_sa_failure(private_child_create_t *this,
									message_t *message)
{
	if (message->get_exchange_type(message) == IKE_AUTH &&
		lib->settings->get_bool(lib->settings,
								"charon.close_ike_on_child_failure", FALSE))
	{
		/* we delay the delete for 100ms, as the IKE_AUTH response must arrive
		 * first */
		DBG1(DBG_IKE, "closing IKE_SA due CHILD_SA setup failure");
		charon->scheduler->schedule_job(charon->scheduler, (job_t*)
			delete_ike_sa_job_create(this->ike_sa->get_id(this->ike_sa), TRUE),
			100);
	}
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_child_create_t *this, message_t *message)
{
	payload_t *payload;
	iterator_t *iterator;
	bool no_dh = TRUE;

	switch (message->get_exchange_type(message))
	{
		case IKE_SA_INIT:
			return get_nonce(message, &this->my_nonce);
		case CREATE_CHILD_SA:
			if (generate_nonce(&this->my_nonce) != SUCCESS)
			{
				message->add_notify(message, FALSE, NO_PROPOSAL_CHOSEN,
									chunk_empty);
				return SUCCESS;
			}
			no_dh = FALSE;
			break;
		case IKE_AUTH:
			if (message->get_payload(message, EXTENSIBLE_AUTHENTICATION))
			{
				/* wait until extensible authentication completed, if used */
				return NEED_MORE;
			}
		default:
			break;
	}
	
	if (this->ike_sa->get_state(this->ike_sa) == IKE_REKEYING)
	{
		SIG(CHILD_UP_FAILED, "unable to create CHILD_SA while rekeying IKE_SA");
		message->add_notify(message, TRUE, NO_ADDITIONAL_SAS, chunk_empty);
		return SUCCESS;
	}
	
	if (this->config == NULL)
	{
		SIG(CHILD_UP_FAILED, "traffic selectors %#R=== %#R inacceptable",
			this->tsr, this->tsi);
		message->add_notify(message, FALSE, TS_UNACCEPTABLE, chunk_empty);
		handle_child_sa_failure(this, message);
		return SUCCESS;
	}
	
	/* check if ike_config_t included non-critical error notifies */
	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		if (payload->get_type(payload) == NOTIFY)
		{
			notify_payload_t *notify = (notify_payload_t*)payload;
			
			switch (notify->get_notify_type(notify))
			{
				case INTERNAL_ADDRESS_FAILURE:
				case FAILED_CP_REQUIRED:
				{
					SIG(CHILD_UP_FAILED, "configuration payload negotation "
						"failed, no CHILD_SA built");
					iterator->destroy(iterator);
					handle_child_sa_failure(this, message);
					return SUCCESS;
				}
				default:
					break;
			}
		}
	}
	iterator->destroy(iterator);
	
	this->child_sa = child_sa_create(
			this->ike_sa->get_my_host(this->ike_sa),
			this->ike_sa->get_other_host(this->ike_sa),
			this->ike_sa->get_my_id(this->ike_sa),
			this->ike_sa->get_other_id(this->ike_sa), this->config, this->reqid,
			this->ike_sa->has_condition(this->ike_sa, COND_NAT_ANY));
	
	if (this->config->use_ipcomp(this->config) &&
		this->ipcomp_received != IPCOMP_NONE)
	{
		this->ipcomp = this->ipcomp_received;
		build_ipcomp_supported_notify(this, message);
	}
	else if (this->ipcomp_received != IPCOMP_NONE)
	{
		DBG1(DBG_IKE, "received %N notify but IPComp is disabled, ignoring",
			 notify_type_names, IPCOMP_SUPPORTED);
	}
	
	switch (select_and_install(this, no_dh))
	{
		case SUCCESS:
			break;
		case NOT_FOUND:
			message->add_notify(message, FALSE, TS_UNACCEPTABLE, chunk_empty);
			handle_child_sa_failure(this, message);
			return SUCCESS;
		case INVALID_ARG:
		{
			u_int16_t group = htons(this->dh_group);
			message->add_notify(message, FALSE, INVALID_KE_PAYLOAD,
								chunk_from_thing(group));
			handle_child_sa_failure(this, message);
			return SUCCESS;
		}
		case FAILED:
		default:
			message->add_notify(message, FALSE, NO_PROPOSAL_CHOSEN, chunk_empty);
			handle_child_sa_failure(this, message);
			return SUCCESS;
	}
	
	build_payloads(this, message);
	
	SIG(CHILD_UP_SUCCESS, "CHILD_SA '%s' established successfully",
						   this->child_sa->get_name(this->child_sa));

	return SUCCESS;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_child_create_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;
	bool no_dh = TRUE;

	switch (message->get_exchange_type(message))
	{
		case IKE_SA_INIT:
			return get_nonce(message, &this->other_nonce);
		case CREATE_CHILD_SA:
			get_nonce(message, &this->other_nonce);
			no_dh = FALSE;
			break;
		case IKE_AUTH:
			if (message->get_payload(message, EXTENSIBLE_AUTHENTICATION))
			{
				/* wait until extensible authentication completed, if used */
				return NEED_MORE;
			}
		default:
			break;
	}

	/* check for erronous notifies */
	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		if (payload->get_type(payload) == NOTIFY)
		{
			notify_payload_t *notify = (notify_payload_t*)payload;
			notify_type_t type = notify->get_notify_type(notify);
			
			switch (type)
			{
				/* handle notify errors related to CHILD_SA only */
				case NO_PROPOSAL_CHOSEN:
				case SINGLE_PAIR_REQUIRED:
				case NO_ADDITIONAL_SAS:
				case INTERNAL_ADDRESS_FAILURE:
				case FAILED_CP_REQUIRED:
				case TS_UNACCEPTABLE:
				case INVALID_SELECTORS:
				{
					SIG(CHILD_UP_FAILED, "received %N notify, no CHILD_SA built",
						notify_type_names, type);
					iterator->destroy(iterator);
					handle_child_sa_failure(this, message);
					/* an error in CHILD_SA creation is not critical */
					return SUCCESS;
				}
				case INVALID_KE_PAYLOAD:
				{
					chunk_t data;
					diffie_hellman_group_t bad_group;
					
					bad_group = this->dh_group;
					data = notify->get_notification_data(notify);
					this->dh_group = ntohs(*((u_int16_t*)data.ptr));
					DBG1(DBG_IKE, "peer didn't accept DH group %N, "
						 "it requested %N", diffie_hellman_group_names,
						 bad_group, diffie_hellman_group_names, this->dh_group);
					
					this->public.task.migrate(&this->public.task, this->ike_sa);
					iterator->destroy(iterator);
					return NEED_MORE;
				}
				default:
					break;
			}
		}
	}
	iterator->destroy(iterator);
	
	process_payloads(this, message);
	
	if (this->ipcomp == IPCOMP_NONE && this->ipcomp_received != IPCOMP_NONE)
	{
		SIG(CHILD_UP_FAILED, "received an IPCOMP_SUPPORTED notify but we did not "
					"send one previously, no CHILD_SA built");
		handle_child_sa_failure(this, message);
		return SUCCESS;
	}
	else if (this->ipcomp != IPCOMP_NONE && this->ipcomp_received == IPCOMP_NONE)
	{
		DBG1(DBG_IKE, "peer didn't accept our proposed IPComp transforms, "
				"IPComp is disabled");
		this->ipcomp = IPCOMP_NONE;
	}
	else if (this->ipcomp != IPCOMP_NONE && this->ipcomp != this->ipcomp_received)
	{
		SIG(CHILD_UP_FAILED, "received an IPCOMP_SUPPORTED notify for a transform "
					"we did not propose, no CHILD_SA built");
		handle_child_sa_failure(this, message);
		return SUCCESS;
	}
	
	if (select_and_install(this, no_dh) == SUCCESS)
	{
		SIG(CHILD_UP_SUCCESS, "CHILD_SA '%s' established successfully",
							   this->child_sa->get_name(this->child_sa));
	}
	else
	{
		handle_child_sa_failure(this, message);
	}
	return SUCCESS;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_child_create_t *this)
{
	return CHILD_CREATE;
}

/**
 * Implementation of child_create_t.use_reqid
 */
static void use_reqid(private_child_create_t *this, u_int32_t reqid)
{
	this->reqid = reqid;
}

/**
 * Implementation of child_create_t.get_child
 */
static child_sa_t* get_child(private_child_create_t *this)
{
	return this->child_sa;
}

/**
 * Implementation of child_create_t.get_lower_nonce
 */
static chunk_t get_lower_nonce(private_child_create_t *this)
{	
	if (memcmp(this->my_nonce.ptr, this->other_nonce.ptr,
			   min(this->my_nonce.len, this->other_nonce.len)) < 0)
	{
		return this->my_nonce;
	}
	else
	{
		return this->other_nonce;
	}
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_child_create_t *this, ike_sa_t *ike_sa)
{
	chunk_free(&this->my_nonce);
	chunk_free(&this->other_nonce);
	if (this->tsi)
	{
		this->tsr->destroy_offset(this->tsr, offsetof(traffic_selector_t, destroy));
	}
	if (this->tsr)
	{
		this->tsi->destroy_offset(this->tsi, offsetof(traffic_selector_t, destroy));
	}
	DESTROY_IF(this->child_sa);
	DESTROY_IF(this->proposal);
	DESTROY_IF(this->dh);
	if (this->proposals)
	{
		this->proposals->destroy_offset(this->proposals, offsetof(proposal_t, destroy));
	}
	
	this->ike_sa = ike_sa;
	this->proposals = NULL;
	this->tsi = NULL;
	this->tsr = NULL;
	this->dh = NULL;
	this->child_sa = NULL;
	this->mode = MODE_TUNNEL;
	this->ipcomp = IPCOMP_NONE;
	this->ipcomp_received = IPCOMP_NONE;
	this->other_cpi = 0;
	this->reqid = 0;
	this->established = FALSE;
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_child_create_t *this)
{
	chunk_free(&this->my_nonce);
	chunk_free(&this->other_nonce);
	if (this->tsi)
	{
		this->tsr->destroy_offset(this->tsr, offsetof(traffic_selector_t, destroy));
	}
	if (this->tsr)
	{
		this->tsi->destroy_offset(this->tsi, offsetof(traffic_selector_t, destroy));
	}
	if (!this->established)
	{
		DESTROY_IF(this->child_sa);
	}
	DESTROY_IF(this->proposal);
	DESTROY_IF(this->dh);
	if (this->proposals)
	{
		this->proposals->destroy_offset(this->proposals, offsetof(proposal_t, destroy));
	}
	
	DESTROY_IF(this->config);
	free(this);
}

/*
 * Described in header.
 */
child_create_t *child_create_create(ike_sa_t *ike_sa, child_cfg_t *config)
{
	private_child_create_t *this = malloc_thing(private_child_create_t);

	this->public.get_child = (child_sa_t*(*)(child_create_t*))get_child;
	this->public.get_lower_nonce = (chunk_t(*)(child_create_t*))get_lower_nonce;
	this->public.use_reqid = (void(*)(child_create_t*,u_int32_t))use_reqid;
	this->public.task.get_type = (task_type_t(*)(task_t*))get_type;
	this->public.task.migrate = (void(*)(task_t*,ike_sa_t*))migrate;
	this->public.task.destroy = (void(*)(task_t*))destroy;
	if (config)
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_i;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_i;
		this->initiator = TRUE;
		config->get_ref(config);
	}
	else
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_r;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_r;
		this->initiator = FALSE;
	}
	
	this->ike_sa = ike_sa;
	this->config = config;
	this->my_nonce = chunk_empty;
	this->other_nonce = chunk_empty;
	this->proposals = NULL;
	this->proposal = NULL;
	this->tsi = NULL;
	this->tsr = NULL;
	this->dh = NULL;
	this->dh_group = MODP_NONE;
	this->child_sa = NULL;
	this->mode = MODE_TUNNEL;
	this->ipcomp = IPCOMP_NONE;
	this->ipcomp_received = IPCOMP_NONE;
	this->other_cpi = 0;
	this->reqid = 0;
	this->established = FALSE;
	
	return &this->public;
}
