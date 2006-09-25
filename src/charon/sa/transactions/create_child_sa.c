/**
 * @file create_child_sa.c
 *
 * @brief Implementation of create_child_sa_t transaction.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#include "create_child_sa.h"

#include <string.h>

#include <daemon.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/ts_payload.h>
#include <sa/transactions/delete_child_sa.h>
#include <utils/randomizer.h>


typedef struct private_create_child_sa_t private_create_child_sa_t;

/**
 * Private members of a create_child_sa_t object..
 */
struct private_create_child_sa_t {
	
	/**
	 * Public methods and transaction_t interface.
	 */
	create_child_sa_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Message sent by our peer, if already generated
	 */
	message_t *message;
	
	/**
	 * Message ID this transaction uses
	 */
	u_int32_t message_id;
	
	/**
	 * Times we did send the request
	 */
	u_int32_t requested;
	
	/**
	 * initiators inbound SPI of the CHILD_SA which gets rekeyed
	 */
	u_int32_t rekey_spi;
	
	/**
	 * reqid to use for new CHILD_SA
	 */
	u_int32_t reqid;
	
	/**
	 * policy definition used
	 */
	policy_t *policy;
	
	/**
	 * Negotiated proposal used for CHILD_SA
	 */
	proposal_t *proposal;
	
	/**
	 * initiator chosen nonce
	 */
	chunk_t nonce_i;
	
	/**
	 * responder chosen nonce
	 */
	chunk_t nonce_r;
	
	/**
	 * lower of the nonces of a simultaneus rekeying request
	 */
	chunk_t nonce_s;
	
	/**
	 * Negotiated traffic selectors for initiator
	 */
	linked_list_t *tsi;
	
	/**
	 * Negotiated traffic selectors for responder
	 */
	linked_list_t *tsr;
	
	/**
	 * CHILD_SA created by this transaction
	 */
	child_sa_t *child_sa;
	
	/**
	 * CHILD_SA rekeyed if we are rekeying
	 */
	child_sa_t *rekeyed_sa;
	
	/**
	 * Have we lost the simultaneous rekeying nonce compare?
	 */
	bool lost;
	
	/**
	 * source of randomness
	 */
	randomizer_t *randomizer;
	
	/**
	 * Assigned logger.
	 */
	logger_t *logger;
};

/**
 * Implementation of transaction_t.get_message_id.
 */
static u_int32_t get_message_id(private_create_child_sa_t *this)
{
	return this->message_id;
}

/**
 * Implementation of transaction_t.requested.
 */
static u_int32_t requested(private_create_child_sa_t *this)
{
	return this->requested++;
}

/**
 * Implementation of create_child_sa_t.set_policy.
 */
static void set_policy(private_create_child_sa_t *this, policy_t *policy)
{
	this->policy = policy;
}

/**
 * Implementation of create_child_sa_t.set_reqid.
 */
static void set_reqid(private_create_child_sa_t *this, u_int32_t reqid)
{
	this->reqid = reqid;
}

/**
 * Implementation of create_child_sa_t.rekeys_child.
 */
static void rekeys_child(private_create_child_sa_t *this, child_sa_t *child_sa)
{
	this->rekeyed_sa = child_sa;
}

/**
 * Implementation of create_child_sa_t.cancel.
 */
static void cancel(private_create_child_sa_t *this)
{
	this->rekeyed_sa = NULL;
	this->lost = TRUE;
}

/**
 * destroy a list of traffic selectors
 */
static void destroy_ts_list(linked_list_t *list)
{
	if (list)
	{
		traffic_selector_t *ts;
		while (list->remove_last(list, (void**)&ts) == SUCCESS)
		{
			ts->destroy(ts);
		}
		list->destroy(list);
	}
}

/**
 * destroy a list of proposals
 */
static void destroy_proposal_list(linked_list_t *list)
{
	proposal_t *proposal;
	
	while (list->remove_last(list, (void**)&proposal) == SUCCESS)
	{
		proposal->destroy(proposal);
	}
	list->destroy(list);
}

/**
 * Implementation of transaction_t.get_request.
 */
static status_t get_request(private_create_child_sa_t *this, message_t **result)
{
	message_t *request;
	host_t *me, *other;
	identification_t *my_id, *other_id;
	
	/* check if we already have built a message (retransmission) */
	if (this->message)
	{
		*result = this->message;
		return SUCCESS;
	}
	
	/* check if we are not already rekeying */
	if (this->rekeyed_sa)
	{
		switch (this->rekeyed_sa->get_state(this->rekeyed_sa))
		{
			case CHILD_REKEYING:
				this->logger->log(this->logger, ERROR,
								  "rekeying a CHILD_SA which is already rekeying, aborted");
				return FAILED;
			case CHILD_DELETING:
				this->logger->log(this->logger, ERROR,
								  "rekeying a CHILD_SA which is deleting, aborted");
				return FAILED;
			default:
				break;
		}
		this->rekeyed_sa->set_state(this->rekeyed_sa, CHILD_REKEYING);
	}
	
	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	my_id = this->ike_sa->get_my_id(this->ike_sa);
	other_id = this->ike_sa->get_other_id(this->ike_sa);
	
	/* build the request */
	request = message_create();
	request->set_source(request, me->clone(me));
	request->set_destination(request, other->clone(other));
	request->set_exchange_type(request, CREATE_CHILD_SA);
	request->set_request(request, TRUE);
	request->set_ike_sa_id(request, this->ike_sa->get_id(this->ike_sa));
	*result = request;
	this->message = request;
	
	{	/* build SA payload */
		sa_payload_t *sa_payload;
		linked_list_t *proposals;
		bool use_natt;
		
		/* get a policy, if we are rekeying */
		if (this->rekeyed_sa)
		{
			linked_list_t *my_ts, *other_ts;
			identification_t *my_id, *other_id;
			
			my_ts = this->rekeyed_sa->get_my_traffic_selectors(this->rekeyed_sa);
			other_ts = this->rekeyed_sa->get_other_traffic_selectors(this->rekeyed_sa);
			my_id = this->ike_sa->get_my_id(this->ike_sa);
			other_id = this->ike_sa->get_other_id(this->ike_sa);
			
			this->policy = charon->policies->get_policy(charon->policies,
														my_id, other_id,
														my_ts, other_ts,
													    me, other);
			
			this->reqid = this->rekeyed_sa->get_reqid(this->rekeyed_sa);
			
			if (this->policy == NULL)
			{
				this->logger->log(this->logger, ERROR,
								  "no policy found to rekey CHILD_SA with reqid %d",
								  this->reqid);
				return FAILED;
			}
		}
		
		proposals = this->policy->get_proposals(this->policy);
		use_natt = this->ike_sa->is_natt_enabled(this->ike_sa);
		this->child_sa = child_sa_create(this->reqid, me, other, my_id, other_id,
							this->policy->get_soft_lifetime(this->policy),
							this->policy->get_hard_lifetime(this->policy),
							this->policy->get_updown(this->policy),
							this->policy->get_hostaccess(this->policy),
							use_natt);
		this->child_sa->set_name(this->child_sa, this->policy->get_name(this->policy));
		if (this->child_sa->alloc(this->child_sa, proposals) != SUCCESS)
		{
			this->logger->log(this->logger, ERROR,
							  "could not install CHILD_SA, CHILD_SA creation aborted");
			return FAILED;
		}
		sa_payload = sa_payload_create_from_proposal_list(proposals);
		destroy_proposal_list(proposals);
		request->add_payload(request, (payload_t*)sa_payload);
	}
	
	{	/* build the NONCE payload for us (initiator) */
		nonce_payload_t *nonce_payload;
		
		if (this->randomizer->allocate_pseudo_random_bytes(this->randomizer, 
			NONCE_SIZE, &this->nonce_i) != SUCCESS)
		{
			return FAILED;
		}
		nonce_payload = nonce_payload_create();
		nonce_payload->set_nonce(nonce_payload, this->nonce_i);
		request->add_payload(request, (payload_t*)nonce_payload);
	}
	
	{	/* build TSi payload */
		linked_list_t *ts_list;
		ts_payload_t *ts_payload;
		
		ts_list = this->policy->get_my_traffic_selectors(this->policy, me);
		ts_payload = ts_payload_create_from_traffic_selectors(TRUE, ts_list);
		destroy_ts_list(ts_list);
		request->add_payload(request, (payload_t*)ts_payload);
	}
	
	{	/* build TSr payload */
		linked_list_t *ts_list;
		ts_payload_t *ts_payload;
		
		ts_list = this->policy->get_other_traffic_selectors(this->policy, other);
		ts_payload = ts_payload_create_from_traffic_selectors(FALSE, ts_list);
		destroy_ts_list(ts_list);
		request->add_payload(request, (payload_t*)ts_payload);
	}
	
	if (this->rekeyed_sa)
	{	/* add REKEY_SA notify if we are rekeying */
		notify_payload_t *notify;
		protocol_id_t protocol;
		
		protocol = this->rekeyed_sa->get_protocol(this->rekeyed_sa);
		notify = notify_payload_create_from_protocol_and_type(protocol, REKEY_SA);
		notify->set_spi(notify, this->rekeyed_sa->get_spi(this->rekeyed_sa, TRUE));
		request->add_payload(request, (payload_t*)notify);
		
		/* register us as rekeying to detect multiple rekeying */
		this->rekeyed_sa->set_rekeying_transaction(this->rekeyed_sa, &this->public);
	}
	
	this->message_id = this->ike_sa->get_next_message_id(this->ike_sa);
	request->set_message_id(request, this->message_id);
	
	return SUCCESS;
}

/**
 * Handle all kind of notifys
 */
static status_t process_notifys(private_create_child_sa_t *this, notify_payload_t *notify_payload)
{
	notify_type_t notify_type = notify_payload->get_notify_type(notify_payload);
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "process notify type %s",
					  mapping_find(notify_type_m, notify_type));

	switch (notify_type)
	{
		case SINGLE_PAIR_REQUIRED:
		{
			this->logger->log(this->logger, AUDIT, 
							  "received a SINGLE_PAIR_REQUIRED notify");
			return FAILED;
		}
		case TS_UNACCEPTABLE:
		{
			this->logger->log(this->logger, CONTROL, 
							  "received TS_UNACCEPTABLE notify");
			return FAILED;
		}
		case NO_PROPOSAL_CHOSEN:
		{
			this->logger->log(this->logger, CONTROL,
							  "received NO_PROPOSAL_CHOSEN notify");
			return FAILED;
		}
		case REKEY_SA:
		{
			u_int32_t spi;
			protocol_id_t protocol;
			
			protocol = notify_payload->get_protocol_id(notify_payload);
			switch (protocol)
			{
				case PROTO_AH:
				case PROTO_ESP:
					spi = notify_payload->get_spi(notify_payload);
					this->rekeyed_sa = this->ike_sa->get_child_sa(this->ike_sa, 
																  protocol, spi,
																  FALSE);
					break;
				default:
					break;
			}
			return SUCCESS;
		}
		default:
		{
			if (notify_type < 16383)
			{
				this->logger->log(this->logger, AUDIT, 
								  "received %s notify error (%d), CHILD_SA creation failed",
								  mapping_find(notify_type_m, notify_type),
								  notify_type);
				return FAILED;	
			}
			else
			{
				this->logger->log(this->logger, CONTROL, 
								  "received %s notify (%d), ignored",
								  mapping_find(notify_type_m, notify_type),
								  notify_type);
				return SUCCESS;
			}
		}
	}
}

/**
 * Build a notify message.
 */
static void build_notify(notify_type_t type, chunk_t data, message_t *message, bool flush_message)
{
	notify_payload_t *notify;
	
	if (flush_message)
	{
		payload_t *payload;
		iterator_t *iterator = message->get_payload_iterator(message);
		while (iterator->iterate(iterator, (void**)&payload))
		{
			payload->destroy(payload);
			iterator->remove(iterator);
		}
		iterator->destroy(iterator);
	}
	
	notify = notify_payload_create();
	notify->set_notify_type(notify, type);
	notify->set_notification_data(notify, data);
	message->add_payload(message, (payload_t*)notify);
}

/**
 * Install a CHILD_SA for usage
 */
static status_t install_child_sa(private_create_child_sa_t *this, bool initiator)
{
	prf_plus_t *prf_plus;
	chunk_t seed;
	status_t status;
	
	seed = chunk_alloc(this->nonce_i.len + this->nonce_r.len);
	memcpy(seed.ptr, this->nonce_i.ptr, this->nonce_i.len);
	memcpy(seed.ptr + this->nonce_i.len, this->nonce_r.ptr, this->nonce_r.len);
	prf_plus = prf_plus_create(this->ike_sa->get_child_prf(this->ike_sa), seed);
	chunk_free(&seed);
	
	if (initiator)
	{
		status = this->child_sa->update(this->child_sa, this->proposal, prf_plus);
	}
	else
	{
		status = this->child_sa->add(this->child_sa, this->proposal, prf_plus);
	}
	prf_plus->destroy(prf_plus);
	if (status != SUCCESS)
	{
		return DESTROY_ME;
	}
	if (initiator)
	{
		status = this->child_sa->add_policies(this->child_sa, this->tsi, this->tsr);
	}
	else
	{
		status = this->child_sa->add_policies(this->child_sa, this->tsr, this->tsi);
	}
	if (status != SUCCESS)
	{
		return DESTROY_ME;
	}
	
	/* add to IKE_SA, and remove from transaction */
	this->child_sa->set_state(this->child_sa, CHILD_INSTALLED);
	this->ike_sa->add_child_sa(this->ike_sa, this->child_sa);
	this->child_sa = NULL;
	return SUCCESS;
}

/**
 * Implementation of transaction_t.get_response.
 */
static status_t get_response(private_create_child_sa_t *this, message_t *request, 
							 message_t **result, transaction_t **next)
{
	host_t *me, *other;
	identification_t *my_id, *other_id;
	message_t *response;
	status_t status;
	iterator_t *payloads;
	sa_payload_t *sa_request = NULL;
	nonce_payload_t *nonce_request = NULL;
	ts_payload_t *tsi_request = NULL;
	ts_payload_t *tsr_request = NULL;
	nonce_payload_t *nonce_response;
	
	/* check if we already have built a response (retransmission) */
	if (this->message)
	{
		*result = this->message;
		return SUCCESS;
	}
	
	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	my_id = this->ike_sa->get_my_id(this->ike_sa);
	other_id = this->ike_sa->get_other_id(this->ike_sa);
	this->message_id = request->get_message_id(request);
	
	/* set up response */
	response = message_create();
	response->set_source(response, me->clone(me));
	response->set_destination(response, other->clone(other));
	response->set_exchange_type(response, CREATE_CHILD_SA);
	response->set_request(response, FALSE);
	response->set_message_id(response, this->message_id);
	response->set_ike_sa_id(response, this->ike_sa->get_id(this->ike_sa));
	this->message = response;
	*result = response;
	
	/* check message type */
	if (request->get_exchange_type(request) != CREATE_CHILD_SA)
	{
		this->logger->log(this->logger, ERROR,
						  "CREATE_CHILD_SA response of invalid type, aborted");
		return FAILED;
	}
	
	/* we do not allow the creation of new CHILDren/rekeying when IKE_SA is
	 * rekeying */
	if (this->ike_sa->get_state(this->ike_sa) == IKE_REKEYING ||
		this->ike_sa->get_state(this->ike_sa) == IKE_DELETING)
	{
		build_notify(NO_ADDITIONAL_SAS, CHUNK_INITIALIZER, response, TRUE);
		this->logger->log(this->logger, AUDIT, 
						  "unable to create new CHILD_SAs, as rekeying in progress");
		return FAILED;
	}
	
	/* Iterate over all payloads. */
	payloads = request->get_payload_iterator(request);
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		switch (payload->get_type(payload))
		{
			case SECURITY_ASSOCIATION:
				sa_request = (sa_payload_t*)payload;
				break;
			case NONCE:
				nonce_request = (nonce_payload_t*)payload;
				break;
			case TRAFFIC_SELECTOR_INITIATOR:
				tsi_request = (ts_payload_t*)payload;
				break;	
			case TRAFFIC_SELECTOR_RESPONDER:
				tsr_request = (ts_payload_t*)payload;
				break;
			case KEY_EXCHANGE:
			{
				u_int8_t dh_buffer[] = {0x00, 0x00}; /* MODP_NONE */
				chunk_t group = chunk_from_buf(dh_buffer);
				build_notify(INVALID_KE_PAYLOAD, group, response, TRUE);
				this->logger->log(this->logger, CONTROL,
								  "CREATE_CHILD_SA used PFS, sending INVALID_KE_PAYLOAD");
				return FAILED;
			}
			case NOTIFY:
			{
				status = process_notifys(this, (notify_payload_t*)payload);
				if (status != SUCCESS)
				{
					payloads->destroy(payloads);
					return status;
				}
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR, "ignoring %s payload (%d)", 
								  mapping_find(payload_type_m, payload->get_type(payload)),
								  payload->get_type(payload));
				break;
			}
		}
	}
	payloads->destroy(payloads);
	
	/* check if we have all payloads */
	if (!(sa_request && nonce_request && tsi_request && tsr_request))
	{
		build_notify(INVALID_SYNTAX, CHUNK_INITIALIZER, response, TRUE);
		this->logger->log(this->logger, AUDIT, 
						  "request message incomplete, no CHILD_SA created");
		return FAILED;
	}
	
	{	/* process nonce payload */
		this->nonce_i = nonce_request->get_nonce(nonce_request);
		if (this->randomizer->allocate_pseudo_random_bytes(this->randomizer, 
			NONCE_SIZE, &this->nonce_r) != SUCCESS)
		{
			build_notify(NO_PROPOSAL_CHOSEN, CHUNK_INITIALIZER, response, TRUE);
			return FAILED;
		}
		nonce_response = nonce_payload_create();
		nonce_response->set_nonce(nonce_response, this->nonce_r);
	}
	
	{	/* get a policy and process traffic selectors */
		identification_t *my_id, *other_id;
		linked_list_t *my_ts, *other_ts;
		
		my_id = this->ike_sa->get_my_id(this->ike_sa);
		other_id = this->ike_sa->get_other_id(this->ike_sa);
		
		my_ts = tsr_request->get_traffic_selectors(tsr_request);
		other_ts = tsi_request->get_traffic_selectors(tsi_request);
		
		this->policy = charon->policies->get_policy(charon->policies,
													my_id, other_id,
													my_ts, other_ts,
												    me, other);
		if (this->policy)
		{
			this->tsr = this->policy->select_my_traffic_selectors(this->policy, my_ts, me);
			this->tsi = this->policy->select_other_traffic_selectors(this->policy, other_ts, other);
		}
		destroy_ts_list(my_ts);
		destroy_ts_list(other_ts);
		
		if (this->policy == NULL)
		{
			this->logger->log(this->logger, AUDIT,
							  "no acceptable policy found, adding TS_UNACCEPTABLE notify");
			build_notify(TS_UNACCEPTABLE, CHUNK_INITIALIZER, response, TRUE);
			return FAILED;
		}
	}
	
	{	/* process SA payload */
		linked_list_t *proposal_list;
		sa_payload_t *sa_response;
		ts_payload_t *ts_response;
		bool use_natt;
		u_int32_t soft_lifetime, hard_lifetime;
		
		sa_response = sa_payload_create();
		/* get proposals from request, and select one with ours */
		proposal_list = sa_request->get_proposals(sa_request);
		this->logger->log(this->logger, CONTROL|LEVEL1, "selecting proposals:");
		this->proposal = this->policy->select_proposal(this->policy, proposal_list);
		destroy_proposal_list(proposal_list);
		
		/* do we have a proposal? */
		if (this->proposal == NULL)
		{
			this->logger->log(this->logger, AUDIT, 
							  "CHILD_SA proposals unacceptable, adding NO_PROPOSAL_CHOSEN notify");
			build_notify(NO_PROPOSAL_CHOSEN, CHUNK_INITIALIZER, response, TRUE);
			return FAILED;
		}
		/* do we have traffic selectors? */
		else if (this->tsi->get_count(this->tsi) == 0 || this->tsr->get_count(this->tsr) == 0)
		{
			this->logger->log(this->logger, AUDIT,
							  "CHILD_SA traffic selectors unacceptable, adding TS_UNACCEPTABLE notify");
			build_notify(TS_UNACCEPTABLE, CHUNK_INITIALIZER, response, TRUE);
			return FAILED;
		}
		else
		{	/* create child sa */
			if (this->rekeyed_sa)
			{
				this->reqid = this->rekeyed_sa->get_reqid(this->rekeyed_sa);
			}
			soft_lifetime = this->policy->get_soft_lifetime(this->policy);
			hard_lifetime = this->policy->get_hard_lifetime(this->policy);
			use_natt = this->ike_sa->is_natt_enabled(this->ike_sa);
			this->child_sa = child_sa_create(this->reqid, me, other, my_id, other_id,
											 soft_lifetime, hard_lifetime,
											 this->policy->get_updown(this->policy),
											 this->policy->get_hostaccess(this->policy),
											 use_natt);
			this->child_sa->set_name(this->child_sa, this->policy->get_name(this->policy));
			if (install_child_sa(this, FALSE) != SUCCESS)
			{
				this->logger->log(this->logger, ERROR,
								  "installing CHILD_SA failed, adding NO_PROPOSAL_CHOSEN notify");
				build_notify(NO_PROPOSAL_CHOSEN, CHUNK_INITIALIZER, response, TRUE);
				return FAILED;
			}
			/* add proposal to sa payload */
			sa_response->add_proposal(sa_response, this->proposal);
		}
		response->add_payload(response, (payload_t*)sa_response);
		
		/* add nonce/ts payload after sa payload */
		response->add_payload(response, (payload_t *)nonce_response);
		ts_response = ts_payload_create_from_traffic_selectors(TRUE, this->tsi);
		response->add_payload(response, (payload_t*)ts_response);
		ts_response = ts_payload_create_from_traffic_selectors(FALSE, this->tsr);
		response->add_payload(response, (payload_t*)ts_response);
	}
	/* CHILD_SA successfully created. If another transaction is already rekeying
	 * this SA, our lower nonce must be registered for a later nonce compare. */
	if (this->rekeyed_sa)
	{
		private_create_child_sa_t *other;
		
		other = this->rekeyed_sa->get_rekeying_transaction(this->rekeyed_sa);
		if (other)
		{
			/* store our lower nonce in the simultaneus transaction, it 
			 * will later compare it against his nonces when it calls conclude().
			 */
			if (memcmp(this->nonce_i.ptr, this->nonce_r.ptr,
				min(this->nonce_i.len, this->nonce_r.len)) < 0)
			{
				other->nonce_s = chunk_clone(this->nonce_i);
			}
			else
			{
				other->nonce_s = chunk_clone(this->nonce_r);
			}
		}
		this->rekeyed_sa->set_state(this->rekeyed_sa, CHILD_REKEYING);
	}
	return SUCCESS;
}

/**
 * Implementation of transaction_t.conclude
 */
static status_t conclude(private_create_child_sa_t *this, message_t *response, 
						 transaction_t **next)
{
	iterator_t *payloads;
	host_t *me, *other;
	sa_payload_t *sa_payload = NULL;
	nonce_payload_t *nonce_payload = NULL;
	ts_payload_t *tsi_payload = NULL;
	ts_payload_t *tsr_payload = NULL;
	status_t status;
	child_sa_t *new_child = NULL;
	delete_child_sa_t *delete_child_sa;
	
	/* check message type */
	if (response->get_exchange_type(response) != CREATE_CHILD_SA)
	{
		this->logger->log(this->logger, ERROR,
						  "CREATE_CHILD_SA response of invalid type, aborting");
		return FAILED;
	}
	
	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	
	/* Iterate over all payloads to collect them */
	payloads = response->get_payload_iterator(response);
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		switch (payload->get_type(payload))
		{
			case SECURITY_ASSOCIATION:
				sa_payload = (sa_payload_t*)payload;
				break;
			case NONCE:
				nonce_payload = (nonce_payload_t*)payload;
				break;
			case TRAFFIC_SELECTOR_INITIATOR:
				tsi_payload = (ts_payload_t*)payload;
				break;	
			case TRAFFIC_SELECTOR_RESPONDER:
				tsr_payload = (ts_payload_t*)payload;
				break;
			case NOTIFY:
			{
				status = process_notifys(this, (notify_payload_t*)payload);
				if (status != SUCCESS)
				{
					payloads->destroy(payloads);
					return status;
				}
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR, "ignoring %s payload (%d)", 
								  mapping_find(payload_type_m, payload->get_type(payload)),
								  payload->get_type(payload));
				break;
			}
		}
	}
	payloads->destroy(payloads);
	
	if (!(sa_payload && nonce_payload && tsi_payload && tsr_payload))
	{
		this->logger->log(this->logger, AUDIT, "response message incomplete, no CHILD_SA built");
		return FAILED;
	}
	
	{	/* process NONCE payload  */
		this->nonce_r = nonce_payload->get_nonce(nonce_payload);
	}
	
	{	/* process traffic selectors for us */
		linked_list_t *ts_received = tsi_payload->get_traffic_selectors(tsi_payload);
		this->tsi = this->policy->select_my_traffic_selectors(this->policy, ts_received, me);
		destroy_ts_list(ts_received);
	}
	
	{	/* process traffic selectors for other */
		linked_list_t *ts_received = tsr_payload->get_traffic_selectors(tsr_payload);
		this->tsr = this->policy->select_other_traffic_selectors(this->policy, ts_received, other);
		destroy_ts_list(ts_received);
	}
	
	{	/* process sa payload */
		linked_list_t *proposal_list;
		
		proposal_list = sa_payload->get_proposals(sa_payload);
		/* we have to re-check here if other's selection is valid */
		this->proposal = this->policy->select_proposal(this->policy, proposal_list);
		destroy_proposal_list(proposal_list);
		
		/* everything fine to create CHILD? */
		if (this->proposal == NULL ||
			this->tsi->get_count(this->tsi) == 0 ||
			this->tsr->get_count(this->tsr) == 0)
		{
			this->logger->log(this->logger, AUDIT, "CHILD_SA creation failed");
			return FAILED;
		}
		new_child = this->child_sa;
		if (install_child_sa(this, TRUE) != SUCCESS)
		{
			this->logger->log(this->logger, ERROR,
							"installing CHILD_SA failed, no CHILD_SA built");
			return FAILED;
		}
	}
	/* CHILD_SA successfully created. If the other peer initiated rekeying
	 * in the meantime, we detect this by comparing the rekeying_transaction
	 * of the SA. If it changed, we are not alone. Then we must compare the nonces.
	 * If no simultaneous rekeying is going on, we just initiate the delete of
	 * the superseded SA. */
	if (this->rekeyed_sa)
	{	
		/* rekeying finished, update SA status */
		this->rekeyed_sa->set_rekeying_transaction(this->rekeyed_sa, NULL);
		
		if (this->nonce_s.ptr)
		{	/* simlutaneous rekeying is going on, not so good */
			chunk_t this_lowest;
			
			/* first get our lowest nonce */
			if (memcmp(this->nonce_i.ptr, this->nonce_r.ptr, 
				min(this->nonce_i.len, this->nonce_r.len)) < 0)
			{
				this_lowest = this->nonce_i;
			}
			else
			{
				this_lowest = this->nonce_r;
			}
			/* then compare against other lowest nonce */
			if (memcmp(this_lowest.ptr, this->nonce_s.ptr, 
				min(this_lowest.len, this->nonce_s.len)) < 0)
			{
				this->logger->log(this->logger, ERROR,
								  "detected simultaneous CHILD_SA rekeying, deleting ours");
				this->lost = TRUE;
			}
			else
			{
				this->logger->log(this->logger, ERROR,
								  "detected simultaneous CHILD_SA rekeying, but ours is preferred");
			}
		}	
		/* delete the old SA if we have won the rekeying nonce compare*/
		if (!this->lost)
		{
			delete_child_sa = delete_child_sa_create(this->ike_sa);
			delete_child_sa->set_child_sa(delete_child_sa, this->rekeyed_sa);
			*next = (transaction_t*)delete_child_sa;
		}
	}
	if (this->lost)
	{
		/* we have lost simlutaneous rekeying, delete the CHILD_SA we just have created */
		delete_child_sa = delete_child_sa_create(this->ike_sa);
		delete_child_sa->set_child_sa(delete_child_sa, new_child);
		*next = (transaction_t*)delete_child_sa;
	}
	return SUCCESS;
}

/**
 * implements transaction_t.destroy
 */
static void destroy(private_create_child_sa_t *this)
{
	DESTROY_IF(this->message);
	DESTROY_IF(this->proposal);
	DESTROY_IF(this->child_sa);
	DESTROY_IF(this->policy);
	destroy_ts_list(this->tsi);
	destroy_ts_list(this->tsr);
	chunk_free(&this->nonce_i);
	chunk_free(&this->nonce_r);
	chunk_free(&this->nonce_s);
	this->randomizer->destroy(this->randomizer);
	free(this);
}

/*
 * Described in header.
 */
create_child_sa_t *create_child_sa_create(ike_sa_t *ike_sa)
{
	private_create_child_sa_t *this = malloc_thing(private_create_child_sa_t);
	
	/* transaction interface functions */
	this->public.transaction.get_request = (status_t(*)(transaction_t*,message_t**))get_request;
	this->public.transaction.get_response = (status_t(*)(transaction_t*,message_t*,message_t**,transaction_t**))get_response;
	this->public.transaction.conclude = (status_t(*)(transaction_t*,message_t*,transaction_t**))conclude;
	this->public.transaction.get_message_id = (u_int32_t(*)(transaction_t*))get_message_id;
	this->public.transaction.requested = (u_int32_t(*)(transaction_t*))requested;
	this->public.transaction.destroy = (void(*)(transaction_t*))destroy;
	
	/* public functions */
	this->public.set_policy = (void(*)(create_child_sa_t*,policy_t*))set_policy;
	this->public.set_reqid = (void(*)(create_child_sa_t*,u_int32_t))set_reqid;
	this->public.rekeys_child = (void(*)(create_child_sa_t*,child_sa_t*))rekeys_child;
	this->public.cancel = (void(*)(create_child_sa_t*))cancel;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->message_id = 0;
	this->message = NULL;
	this->requested = 0;
	this->rekey_spi = 0;
	this->reqid = 0;
	this->nonce_i = CHUNK_INITIALIZER;
	this->nonce_r = CHUNK_INITIALIZER;
	this->nonce_s = CHUNK_INITIALIZER;
	this->child_sa = NULL;
	this->rekeyed_sa = NULL;
	this->lost = FALSE;
	this->proposal = NULL;
	this->policy = NULL;
	this->tsi = NULL;
	this->tsr = NULL;
	this->randomizer = randomizer_create();
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);
	
	return &this->public;
}
