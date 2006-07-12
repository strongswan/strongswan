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
	 * connection of IKE_SA
	 */
	connection_t *connection;
	
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
 * Implementation of transaction_t.get_request.
 */
static status_t get_request(private_create_child_sa_t *this, message_t **result)
{
	message_t *request;
	host_t *me, *other;
	
	/* check if we are not already rekeying */
	if (this->rekeyed_sa && 
		this->rekeyed_sa->get_rekeying_transaction(this->rekeyed_sa))
	{
		this->logger->log(this->logger, ERROR,
						  "rekeying a CHILD_SA which is already rekeying, aborted");
		return FAILED;
	}
	
	/* check if we already have built a message (retransmission) */
	if (this->message)
	{
		*result = this->message;
		return SUCCESS;
	}
	
	this->connection = this->ike_sa->get_connection(this->ike_sa);
	me = this->connection->get_my_host(this->connection);
	other = this->connection->get_other_host(this->connection);
	this->policy = this->ike_sa->get_policy(this->ike_sa);
	
	/* build the request */
	request = message_create();
	request->set_source(request, me->clone(me));
	request->set_destination(request, other->clone(other));
	request->set_exchange_type(request, CREATE_CHILD_SA);
	request->set_request(request, TRUE);
	request->set_message_id(request, this->message_id);
	request->set_ike_sa_id(request, this->ike_sa->get_id(this->ike_sa));
	*result = request;
	this->message = request;
	
	{	/* build SA payload */
		sa_payload_t *sa_payload;
		linked_list_t *proposals;
		bool use_natt;
		u_int32_t reqid = 0;
		
		if (this->rekeyed_sa)
		{
			reqid = this->rekeyed_sa->get_reqid(this->rekeyed_sa);
		}
		
		proposals = this->policy->get_proposals(this->policy);
		use_natt = this->ike_sa->is_natt_enabled(this->ike_sa);
		this->child_sa = child_sa_create(reqid, me, other,
							this->policy->get_soft_lifetime(this->policy),
							this->policy->get_hard_lifetime(this->policy),
							use_natt);
		if (this->child_sa->alloc(this->child_sa, proposals) != SUCCESS)
		{
			this->logger->log(this->logger, ERROR,
							  "could not install CHILD_SA, CHILD_SA creation aborted");
			return FAILED;
		}
		sa_payload = sa_payload_create_from_proposal_list(proposals);
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
		
		ts_list = this->policy->get_my_traffic_selectors(this->policy);
		ts_payload = ts_payload_create_from_traffic_selectors(TRUE, ts_list);
		request->add_payload(request, (payload_t*)ts_payload);
	}
	
	{	/* build TSr payload */
		linked_list_t *ts_list;
		ts_payload_t *ts_payload;
		
		ts_list = this->policy->get_other_traffic_selectors(this->policy);
		ts_payload = ts_payload_create_from_traffic_selectors(FALSE, ts_list);
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
								  "received %s notify error (%d), deleting IKE_SA",
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
static void build_notify(notify_type_t type, message_t *message, bool flush_message)
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
	this->ike_sa->add_child_sa(this->ike_sa, this->child_sa);
	this->child_sa = NULL;
	return SUCCESS;
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
 * Implementation of transaction_t.get_response.
 */
static status_t get_response(private_create_child_sa_t *this, message_t *request, 
							 message_t **result, transaction_t **next)
{
	host_t *me, *other;
	message_t *response;
	status_t status;
	iterator_t *payloads;
	sa_payload_t *sa_request = NULL;
	nonce_payload_t *nonce_request = NULL;
	ts_payload_t *tsi_request = NULL;
	ts_payload_t *tsr_request = NULL;
	
	/* check if we already have built a response (retransmission) */
	if (this->message)
	{
		*result = this->message;
		return SUCCESS;
	}
	
	this->connection = this->ike_sa->get_connection(this->ike_sa);
	me = this->connection->get_my_host(this->connection);
	other = this->connection->get_other_host(this->connection);
	this->policy = this->ike_sa->get_policy(this->ike_sa);
	
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
		build_notify(INVALID_SYNTAX, response, TRUE);
		this->logger->log(this->logger, AUDIT, 
						  "request message incomplete, no CHILD_SA created");
		return FAILED;
	}
	
	{	/* process nonce payload */
		nonce_payload_t *nonce_response;
		
		this->nonce_i = nonce_request->get_nonce(nonce_request);
		if (this->randomizer->allocate_pseudo_random_bytes(this->randomizer, 
			NONCE_SIZE, &this->nonce_r) != SUCCESS)
		{
			build_notify(NO_PROPOSAL_CHOSEN, response, TRUE);
			return FAILED;
		}
		nonce_response = nonce_payload_create();
		nonce_response->set_nonce(nonce_response, this->nonce_r);
		response->add_payload(response, (payload_t *)nonce_response);
	}
	
	{	/* process traffic selectors for other */
		linked_list_t *ts_received = tsi_request->get_traffic_selectors(tsi_request);
		this->tsi = this->policy->select_other_traffic_selectors(this->policy, ts_received);
		destroy_ts_list(ts_received);
	}
	
	{	/* process traffic selectors for us */
		linked_list_t *ts_received = ts_received = tsr_request->get_traffic_selectors(tsr_request);
		this->tsr = this->policy->select_my_traffic_selectors(this->policy, ts_received);
		destroy_ts_list(ts_received);
	}
	
	{	/* process SA payload */
		proposal_t *proposal;
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
		/* list is not needed anymore */
		while (proposal_list->remove_last(proposal_list, (void**)&proposal) == SUCCESS)
		{
			proposal->destroy(proposal);
		}
		proposal_list->destroy(proposal_list);

		/* do we have a proposal? */
		if (this->proposal == NULL)
		{
			this->logger->log(this->logger, AUDIT, 
							  "CHILD_SA proposals unacceptable, adding NO_PROPOSAL_CHOSEN notify");
			build_notify(NO_PROPOSAL_CHOSEN, response, TRUE);
			return FAILED;
		}
		/* do we have traffic selectors? */
		else if (this->tsi->get_count(this->tsi) == 0 || this->tsr->get_count(this->tsr) == 0)
		{
			this->logger->log(this->logger, AUDIT,
							  "CHILD_SA traffic selectors unacceptable, adding TS_UNACCEPTABLE notify");
			build_notify(TS_UNACCEPTABLE, response, TRUE);
			return FAILED;
		}
		else
		{	/* create child sa */
			u_int32_t reqid = 0;
		
			if (this->rekeyed_sa)
			{
				reqid = this->rekeyed_sa->get_reqid(this->rekeyed_sa);
			}
			soft_lifetime = this->policy->get_soft_lifetime(this->policy);
			hard_lifetime = this->policy->get_hard_lifetime(this->policy);
			use_natt = this->ike_sa->is_natt_enabled(this->ike_sa);
			this->child_sa = child_sa_create(reqid, me, other,
											 soft_lifetime, hard_lifetime,
											 use_natt);
			if (install_child_sa(this, FALSE) != SUCCESS)
			{
				this->logger->log(this->logger, ERROR,
								  "installing CHILD_SA failed, adding NO_PROPOSAL_CHOSEN notify");
				build_notify(NO_PROPOSAL_CHOSEN, response, TRUE);
				return FAILED;
			}
			/* add proposal to sa payload */
			sa_response->add_proposal(sa_response, this->proposal);
		}
		response->add_payload(response, (payload_t*)sa_response);
		
		/* add ts payload after sa payload */
		ts_response = ts_payload_create_from_traffic_selectors(TRUE, this->tsi);
		response->add_payload(response, (payload_t*)ts_response);
		ts_response = ts_payload_create_from_traffic_selectors(FALSE, this->tsr);
		response->add_payload(response, (payload_t*)ts_response);
	}
	/* CHILD_SA successfully created. We set us as the rekeying transaction of
	 * the rekeyed SA. If we already initiated rekeying of the same SA, we will detect
	 * this later in the conclude() call. */
	if (this->rekeyed_sa)
	{
		this->rekeyed_sa->set_rekeying_transaction(this->rekeyed_sa, &this->public);
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
	
	me = this->connection->get_my_host(this->connection);
	other = this->connection->get_other_host(this->connection);
	
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
		this->tsi = this->policy->select_my_traffic_selectors(this->policy, ts_received);
		destroy_ts_list(ts_received);
	}
	
	{	/* process traffic selectors for other */
		linked_list_t *ts_received = tsr_payload->get_traffic_selectors(tsr_payload);
		this->tsr = this->policy->select_other_traffic_selectors(this->policy, ts_received);
		destroy_ts_list(ts_received);
	}
	
	{	/* process sa payload */
		proposal_t *proposal;
		linked_list_t *proposal_list;
		
		proposal_list = sa_payload->get_proposals(sa_payload);
		/* we have to re-check here if other's selection is valid */
		this->proposal = this->policy->select_proposal(this->policy, proposal_list);
		/* list not needed anymore */
		while (proposal_list->remove_last(proposal_list, (void**)&proposal) == SUCCESS)
		{
			proposal->destroy(proposal);
		}
		proposal_list->destroy(proposal_list);
		
		/* everything fine to create CHILD? */
		if (this->proposal == NULL ||
			this->tsi->get_count(this->tsi) == 0 ||
			this->tsr->get_count(this->tsr) == 0)
		{
			this->logger->log(this->logger, AUDIT,
							  "CHILD_SA creation failed");
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
		private_create_child_sa_t *other;
		
		other = (private_create_child_sa_t*)
					this->rekeyed_sa->get_rekeying_transaction(this->rekeyed_sa);
		
		/* rekeying finished, update SA status */
		this->rekeyed_sa->set_rekeying_transaction(this->rekeyed_sa, NULL);
		
		if (other != this)
		{	/* simlutaneous rekeying is going on, not so good */
			chunk_t this_lowest, other_lowest;
			
			/* check if this has a lower nonce than other */
			if (memcmp(this->nonce_i.ptr, this->nonce_r.ptr, 
				min(this->nonce_i.len, this->nonce_r.len)) < 0)
			{
				this_lowest = this->nonce_i;
			}
			else
			{
				this_lowest = this->nonce_r;
			}
			if (memcmp(other->nonce_i.ptr, other->nonce_r.ptr, 
				min(other->nonce_i.len, other->nonce_r.len)) < 0)
			{
				other_lowest = other->nonce_i;
			}
			else
			{
				other_lowest = other->nonce_r;
			}
			if (memcmp(this_lowest.ptr, other_lowest.ptr, 
				min(this_lowest.len, other_lowest.len)) < 0)
			{
				this->logger->log(this->logger, ERROR,
								  "detected simultaneous CHILD_SA rekeying, but ours is preferred");
			}
			else
			{
				
				this->logger->log(this->logger, ERROR,
								  "detected simultaneous CHILD_SA rekeying, deleting ours");
				this->lost = TRUE;
			}
		}	
		/* delete the old SA if we have won the rekeying nonce compare*/
		if (!this->lost)
		{
			delete_child_sa = delete_child_sa_create(this->ike_sa, this->message_id + 1);
			delete_child_sa->set_child_sa(delete_child_sa, this->rekeyed_sa);
			*next = (transaction_t*)delete_child_sa;
		}
	}
	if (this->lost)
	{
		/* we have lost simlutaneous rekeying, delete the CHILD_SA we just have created */
		delete_child_sa = delete_child_sa_create(this->ike_sa, this->message_id + 1);
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
	if (this->message)
	{
		this->message->destroy(this->message);
	}
	if (this->proposal)
	{
		this->proposal->destroy(this->proposal);
	}
	if (this->child_sa)
	{
		this->child_sa->destroy(this->child_sa);
	}
	destroy_ts_list(this->tsi);
	destroy_ts_list(this->tsr);
	chunk_free(&this->nonce_i);
	chunk_free(&this->nonce_r);
	this->randomizer->destroy(this->randomizer);
	free(this);
}

/*
 * Described in header.
 */
create_child_sa_t *create_child_sa_create(ike_sa_t *ike_sa, u_int32_t message_id)
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
	this->public.rekeys_child = (void(*)(create_child_sa_t*,child_sa_t*))rekeys_child;
	this->public.cancel = (void(*)(create_child_sa_t*))cancel;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->message_id = message_id;
	this->message = NULL;
	this->requested = 0;
	this->rekey_spi = 0;
	this->nonce_i = CHUNK_INITIALIZER;
	this->nonce_r = CHUNK_INITIALIZER;
	this->child_sa = NULL;
	this->rekeyed_sa = NULL;
	this->lost = FALSE;
	this->proposal = NULL;
	this->tsi = NULL;
	this->tsr = NULL;
	this->randomizer = randomizer_create();
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);
	
	return &this->public;
}
