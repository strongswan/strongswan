/**
 * @file child_create.c
 *
 * @brief Implementation of the child_create task.
 *
 */

/*
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
 */

#include "child_create.h"

#include <daemon.h>
#include <crypto/diffie_hellman.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ts_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/notify_payload.h>


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
	 * policy to create the CHILD_SA from
	 */
	policy_t *policy;
	
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
	 * mode the new CHILD_SA uses (transport/tunnel/beet)
	 */
	mode_t mode;
	
	/**
	 * reqid to use if we are rekeying
	 */
	u_int32_t reqid;
	
	/**
	 * CHILD_SA which gets established
	 */
	child_sa_t *child_sa;
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
	status_t status;
	randomizer_t *randomizer = randomizer_create();
	
	status = randomizer->allocate_pseudo_random_bytes(randomizer, NONCE_SIZE,
													  nonce);
	randomizer->destroy(randomizer);
	if (status != SUCCESS)
	{
		DBG1(DBG_IKE, "error generating random nonce value");
		return FAILED;
	}
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
 * Install a CHILD_SA for usage
 */
static status_t select_and_install(private_child_create_t *this)
{
	prf_plus_t *prf_plus;
	status_t status;
	chunk_t nonce_i, nonce_r, seed;
	linked_list_t *my_ts, *other_ts;
	host_t *me, *other, *other_vip, *my_vip;
	
	if (this->proposals == NULL || this->tsi == NULL || this->tsr == NULL)
	{
		SIG(CHILD_UP_FAILED, "SA/TS payloads missing in message");
		return FAILED;
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

	this->proposal = this->policy->select_proposal(this->policy, this->proposals);
	
	if (this->proposal == NULL)
	{
		SIG(CHILD_UP_FAILED, "no acceptable proposal found");
		return FAILED;
	}
	
	if (this->initiator && my_vip)
	{	/* if we have a virtual IP, shorten our TS to the minimum */
		my_ts = this->policy->select_my_traffic_selectors(this->policy, my_ts,
											 			  my_vip);
		/* to setup firewall rules correctly, CHILD_SA needs the virtual IP */
		this->child_sa->set_virtual_ip(this->child_sa, my_vip);
	}
	else
	{	/* shorten in the host2host case only */
		my_ts = this->policy->select_my_traffic_selectors(this->policy, 
															my_ts, me);
	}
	if (other_vip)
	{	/* if other has a virtual IP, shorten it's traffic selectors to it */
		other_ts = this->policy->select_other_traffic_selectors(this->policy,
															other_ts, other_vip);
	}
	else
	{	/* use his host for the host2host case */
		other_ts = this->policy->select_other_traffic_selectors(this->policy,
															other_ts, other);
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
	
	if (this->tsi->get_count(this->tsi) == 0 ||
		this->tsr->get_count(this->tsr) == 0)
	{
		SIG(CHILD_UP_FAILED, "no acceptable traffic selectors found");
		return FAILED;
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
				else if (this->ike_sa->is_natt_enabled(this->ike_sa))
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
	
	seed = chunk_cata("cc", nonce_i, nonce_r);
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
		return status;
	}
	
	status = this->child_sa->add_policies(this->child_sa, my_ts, other_ts,
										  this->mode);
										  
	if (status != SUCCESS)
	{	
		SIG(CHILD_UP_FAILED, "unable to install IPsec policies (SPD) in kernel");
		return status;
	}
	/* add to IKE_SA, and remove from task */
	this->child_sa->set_state(this->child_sa, CHILD_INSTALLED);
	this->ike_sa->add_child_sa(this->ike_sa, this->child_sa);
	this->child_sa = NULL;
	return SUCCESS;
}

/**
 * build the payloads for the message
 */
static void build_payloads(private_child_create_t *this, message_t *message)
{
	sa_payload_t *sa_payload;
	ts_payload_t *ts_payload;
	nonce_payload_t *nonce_payload;

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
	
	/* add TSi/TSr payloads */
	ts_payload = ts_payload_create_from_traffic_selectors(TRUE, this->tsi);
	message->add_payload(message, (payload_t*)ts_payload);
	ts_payload = ts_payload_create_from_traffic_selectors(FALSE, this->tsr);
	message->add_payload(message, (payload_t*)ts_payload);
	
	/* add nonce payload if not in IKE_AUTH */
	if (message->get_exchange_type(message) == CREATE_CHILD_SA)
	{
		nonce_payload = nonce_payload_create();
		nonce_payload->set_nonce(nonce_payload, this->my_nonce);
		message->add_payload(message, (payload_t*)nonce_payload);
	}
	
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
 * Read payloads from message
 */
static void process_payloads(private_child_create_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;
	sa_payload_t *sa_payload;
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
			break;
		default:
			break;
	}
	
	SIG(CHILD_UP_START, "establishing CHILD_SA");
	
	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	vip = this->policy->get_virtual_ip(this->policy, NULL);
	
	if (vip)
	{	/* propose a 0.0.0.0/0 subnet when we use virtual ip */
		this->tsi = this->policy->get_my_traffic_selectors(this->policy, NULL);
		vip->destroy(vip);
	}
	else
	{	/* but shorten a 0.0.0.0/0 subnet to the actual address if host2host */
		this->tsi = this->policy->get_my_traffic_selectors(this->policy, me);
	}
	this->tsr = this->policy->get_other_traffic_selectors(this->policy, other);
	this->proposals = this->policy->get_proposals(this->policy);
	this->mode = this->policy->get_mode(this->policy);
	
	this->child_sa = child_sa_create(me, other,
									 this->ike_sa->get_my_id(this->ike_sa),
									 this->ike_sa->get_other_id(this->ike_sa),
									 this->policy, this->reqid,
									 this->ike_sa->is_natt_enabled(this->ike_sa));
	
	if (this->child_sa->alloc(this->child_sa, this->proposals) != SUCCESS)
	{
		SIG(CHILD_UP_FAILED, "unable to allocate SPIs from kernel");
		return FAILED;
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
	switch (message->get_exchange_type(message))
	{
		case IKE_SA_INIT:
			return get_nonce(message, &this->other_nonce);
		case CREATE_CHILD_SA:
			get_nonce(message, &this->other_nonce);
			break;
		default:
			break;
	}

	process_payloads(this, message);
	
	if (this->tsi == NULL || this->tsr == NULL)
	{
		DBG1(DBG_IKE, "TS payload missing in message");
		return NEED_MORE;
	}

	this->policy = charon->policies->get_policy(charon->policies,
							this->ike_sa->get_my_id(this->ike_sa),
							this->ike_sa->get_other_id(this->ike_sa), 
							this->tsr, this->tsi,
							this->ike_sa->get_my_host(this->ike_sa),
							this->ike_sa->get_other_host(this->ike_sa));
	
	if (this->policy && this->ike_sa->get_policy(this->ike_sa) == NULL)
	{
		this->ike_sa->set_policy(this->ike_sa, this->policy);
	}
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_child_create_t *this, message_t *message)
{
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
			break;
		default:
			break;
	}
	
	if (this->policy == NULL)
	{
		SIG(CHILD_UP_FAILED, "received traffic selectors inacceptable");
		message->add_notify(message, FALSE, TS_UNACCEPTABLE, chunk_empty);
		return SUCCESS;
	}
	
	this->child_sa = child_sa_create(this->ike_sa->get_my_host(this->ike_sa),
									 this->ike_sa->get_other_host(this->ike_sa),
									 this->ike_sa->get_my_id(this->ike_sa),
									 this->ike_sa->get_other_id(this->ike_sa),
									 this->policy, this->reqid,
									 this->ike_sa->is_natt_enabled(this->ike_sa));
	
	if (select_and_install(this) != SUCCESS)
	{
		message->add_notify(message, FALSE, NO_PROPOSAL_CHOSEN, chunk_empty);
		return SUCCESS;
	}
	
	build_payloads(this, message);
	
	SIG(CHILD_UP_SUCCESS, "established CHILD_SA successfully");

	return SUCCESS;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_child_create_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;
	status_t status;

	switch (message->get_exchange_type(message))
	{
		case IKE_SA_INIT:
			return get_nonce(message, &this->other_nonce);
		case CREATE_CHILD_SA:
			get_nonce(message, &this->other_nonce);
			break;
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
			
			if (type < 16383)
			{
				SIG(CHILD_UP_FAILED, "received %N notify error",
					notify_type_names, type);
				iterator->destroy(iterator);
				/* an error in CHILD_SA creation is not critical */
				return SUCCESS;	
			}
		}
	}
	iterator->destroy(iterator);
	
	process_payloads(this, message);
	
	status = select_and_install(this);
	
	SIG(CHILD_UP_SUCCESS, "established CHILD_SA successfully");
	
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
	if (this->proposals)
	{
		this->proposals->destroy_offset(this->proposals, offsetof(proposal_t, destroy));
	}
	
	this->ike_sa = ike_sa;
	this->proposals = NULL;
	this->tsi = NULL;
	this->tsr = NULL;
	this->child_sa = NULL;
	this->mode = MODE_TUNNEL;
	this->reqid = 0;
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
	DESTROY_IF(this->child_sa);
	DESTROY_IF(this->proposal);
	if (this->proposals)
	{
		this->proposals->destroy_offset(this->proposals, offsetof(proposal_t, destroy));
	}
	
	DESTROY_IF(this->policy);
	free(this);
}

/*
 * Described in header.
 */
child_create_t *child_create_create(ike_sa_t *ike_sa, policy_t *policy)
{
	private_child_create_t *this = malloc_thing(private_child_create_t);

	this->public.use_reqid = (void(*)(child_create_t*,u_int32_t))use_reqid;
	this->public.task.get_type = (task_type_t(*)(task_t*))get_type;
	this->public.task.migrate = (void(*)(task_t*,ike_sa_t*))migrate;
	this->public.task.destroy = (void(*)(task_t*))destroy;
	if (policy)
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_i;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_i;
		this->initiator = TRUE;
		policy->get_ref(policy);
	}
	else
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_r;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_r;
		this->initiator = FALSE;
	}
	
	this->ike_sa = ike_sa;
	this->policy = policy;
	this->my_nonce = chunk_empty;
	this->other_nonce = chunk_empty;
	this->proposals = NULL;
	this->proposal = NULL;
	this->tsi = NULL;
	this->tsr = NULL;
	this->child_sa = NULL;
	this->mode = MODE_TUNNEL;
	this->reqid = 0;
	
	return &this->public;
}
