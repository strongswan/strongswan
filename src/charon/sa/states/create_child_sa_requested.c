/**
 * @file create_child_sa_requested.c
 * 
 * @brief State after a CREATE_CHILD_SA request was sent.
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

#include <string.h>

#include "create_child_sa_requested.h"

#include <sa/child_sa.h>
#include <sa/states/delete_ike_sa_requested.h>
#include <sa/states/ike_sa_established.h>
#include <encoding/payloads/ts_payload.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <utils/logger_manager.h>


typedef struct private_create_child_sa_requested_t private_create_child_sa_requested_t;

/**
 * Private data of a create_child_sa_requested_t object.
 */
struct private_create_child_sa_requested_t {
	/**
	 * Public interface of create_child_sa_requested_t.
	 */
	create_child_sa_requested_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	protected_ike_sa_t *ike_sa;
	
	/**
	 * nonce chosen by initiator
	 */
	chunk_t nonce_i;
	
	/**
	 * nonce chosen by the responder
	 */
	chunk_t nonce_r;
	
	/**
	 * Policy to use for new child_sa
	 */
	policy_t *policy;
	
	/**
	 * Proposal negotiated
	 */
	proposal_t *proposal;
	
	/**
	 * Negotiated list of traffic selectors for local site
	 */
	linked_list_t *my_ts;
	
	/**
	 * Negotiated list of traffic selectors for remote site
	 */
	linked_list_t *other_ts;
	
	/**
	 * Child SA to create
	 */
	child_sa_t *child_sa;
	
	/**
	 * Reqid of the old CHILD_SA, when rekeying
	 */
	u_int32_t reqid;
	
	/**
	 * Assigned logger.
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
};

/**
 * Implementation of private_create_child_sa_requested_t.process_sa_payload.
 */
static status_t process_sa_payload(private_create_child_sa_requested_t *this, sa_payload_t *sa_payload)
{
	proposal_t *proposal, *proposal_tmp;
	linked_list_t *proposal_list;
	
	/* get his selected proposal */
	proposal_list = sa_payload->get_proposals(sa_payload);
	/* check count of proposals */
	if (proposal_list->get_count(proposal_list) == 0)
	{
		/* no proposal? we accept this, but no child sa is built */
		this->logger->log(this->logger, AUDIT, "CREATE_CHILD_SA reply contained no proposals. CHILD_SA not created");
		proposal_list->destroy(proposal_list);
		return FAILED;
	}
	if (proposal_list->get_count(proposal_list) > 1)
	{
		this->logger->log(this->logger, AUDIT, "CREATE_CHILD_SA reply contained %d proposals. Aborting",
						  proposal_list->get_count(proposal_list));
		while (proposal_list->remove_last(proposal_list, (void**)&proposal) == SUCCESS)
		{
			proposal->destroy(proposal);
		}
		proposal_list->destroy(proposal_list);
		return FAILED;
	}
	
	/* we have to re-check here if other's selection is valid */
	proposal = this->policy->select_proposal(this->policy, proposal_list);
	/* list not needed anymore */
	while (proposal_list->remove_last(proposal_list, (void**)&proposal_tmp) == SUCCESS)
	{
		proposal_tmp->destroy(proposal_tmp);
	}
	proposal_list->destroy(proposal_list);
	/* got a match? */
	if (proposal == NULL)
	{
		this->logger->log(this->logger, AUDIT, "CREATE_CHILD_SA reply contained a not offered proposal. Aborting");
		return FAILED;
	}
	
	/* apply proposal */
	this->proposal = proposal;
	
	return SUCCESS;
}

/**
 * Implementation of private_create_child_sa_requested_t.process_ts_payload.
 */
static status_t process_ts_payload(private_create_child_sa_requested_t *this, bool ts_initiator, ts_payload_t *ts_payload)
{
	linked_list_t *ts_received, *ts_selected;
	traffic_selector_t *ts;
	
	/* get ts form payload */
	ts_received = ts_payload->get_traffic_selectors(ts_payload);
	/* select ts depending on payload type */
	if (ts_initiator)
	{
		ts_selected = this->policy->select_my_traffic_selectors(this->policy, ts_received);
		this->my_ts = ts_selected;
	}
	else
	{
		ts_selected = this->policy->select_other_traffic_selectors(this->policy, ts_received);
		this->other_ts = ts_selected;
	}
	/* check if the responder selected valid proposals */
	if (ts_selected->get_count(ts_selected) != ts_received->get_count(ts_received))
	{
		this->logger->log(this->logger, AUDIT, "IKE_AUTH reply contained not offered traffic selectors.");
	}
	
	/* cleanup */
	while (ts_received->remove_last(ts_received, (void**)&ts) == SUCCESS)
	{
		ts->destroy(ts);
	}
	ts_received->destroy(ts_received);

	return SUCCESS;
}

/**
 * Implementation of private_create_child_sa_requested_t.process_nonce_payload.
 */
static status_t process_nonce_payload(private_create_child_sa_requested_t *this, nonce_payload_t *nonce_request)
{	
	this->nonce_r = nonce_request->get_nonce(nonce_request);
	return SUCCESS;
}

/**
 * Process a CREATE_CHILD_SA response
 */
static status_t process_message(private_create_child_sa_requested_t *this, message_t *response)
{
	ts_payload_t *tsi_request = NULL, *tsr_request = NULL;
	sa_payload_t *sa_request = NULL;
	nonce_payload_t *nonce_request = NULL;
	ike_sa_id_t *ike_sa_id;
	iterator_t *payloads;
	crypter_t *crypter;
	signer_t *signer;
	status_t status;
	chunk_t seed;
	prf_plus_t *prf_plus;
	child_sa_t *old_child_sa;
	
	this->policy = this->ike_sa->get_policy(this->ike_sa);
	if (response->get_exchange_type(response) != CREATE_CHILD_SA)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "Message of type %s not supported in state create_child_sa_requested",
						  mapping_find(exchange_type_m, response->get_exchange_type(response)));
		return FAILED;
	}
	
	if (response->get_request(response))
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "CREATE_CHILD_SA requests not allowed state create_child_sa_requested");
		/* TODO: our state implementation currently can not handle incoming requests cleanly here.
		 * If a request comes in before an outstanding reply, we can not handle it the correct way.
		 * Currently, we create a ESTABLISHED state and let it process the message... But we
		 * need changes in the whole state mechanism.
		 */
		state_t *state = (state_t*)ike_sa_established_create(this->ike_sa);
		state->process_message(state, response);
		state->destroy(state);
		return SUCCESS;
	}
	
	/* get signer for verification and crypter for decryption */
	ike_sa_id = this->ike_sa->public.get_id(&this->ike_sa->public);
	if (!ike_sa_id->is_initiator(ike_sa_id))
	{
		crypter = this->ike_sa->get_crypter_initiator(this->ike_sa);
		signer = this->ike_sa->get_signer_initiator(this->ike_sa);
	}
	else
	{
		crypter = this->ike_sa->get_crypter_responder(this->ike_sa);
		signer = this->ike_sa->get_signer_responder(this->ike_sa);
	}
	
	/* parse incoming message */
	status = response->parse_body(response, crypter, signer);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "CREATE_CHILD_SA r decryption failed. Ignoring message");
		return status;
	}
	
	/* iterate over incoming payloads. Message is verified, we can be sure there are the required payloads */
	payloads = response->get_payload_iterator(response);
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		
		switch (payload->get_type(payload))
		{
			case SECURITY_ASSOCIATION:
			{
				sa_request = (sa_payload_t*)payload;
				break;
			}
			case TRAFFIC_SELECTOR_INITIATOR:
			{
				tsi_request = (ts_payload_t*)payload;
				break;	
			}
			case TRAFFIC_SELECTOR_RESPONDER:
			{
				tsr_request = (ts_payload_t*)payload;
				break;	
			}
			case NONCE:
			{
				nonce_request = (nonce_payload_t*)payload;
				break;	
			}
			case NOTIFY:
			{
				/* TODO: handle notifys */
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR|LEVEL1, "Ignoring payload %s (%d)", 
								  mapping_find(payload_type_m, payload->get_type(payload)), payload->get_type(payload));
				break;
			}
		}
	}
	/* iterator can be destroyed */
	payloads->destroy(payloads);
	
	/* check if we have all payloads */
	if (!(sa_request && nonce_request && tsi_request && tsr_request))
	{
		this->logger->log(this->logger, AUDIT, "CREATE_CHILD_SA request did not contain all required payloads. Ignored");
		return FAILED;
	}
	
	/* add payloads to it */
	status = process_nonce_payload(this, nonce_request);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}
	status = process_sa_payload(this, sa_request);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}
	status = process_ts_payload(this, TRUE, tsi_request);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}
	status = process_ts_payload(this, FALSE, tsr_request);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}
	
	/* install child SAs for AH and esp */
	if (!this->proposal)
	{
		this->logger->log(this->logger, CONTROL, "Proposal negotiation failed, no CHILD_SA built");
		this->child_sa->destroy(this->child_sa);
		this->child_sa = NULL;
	}
	else if (this->my_ts->get_count(this->my_ts) == 0 || this->other_ts->get_count(this->other_ts) == 0)
	{
		this->logger->log(this->logger, CONTROL, "Traffic selector negotiation failed, no CHILD_SA built");
		this->child_sa->destroy(this->child_sa);
		this->child_sa = NULL;
	}
	else
	{
		seed = chunk_alloc(this->nonce_i.len + this->nonce_r.len);
		memcpy(seed.ptr, this->nonce_i.ptr, this->nonce_i.len);
		memcpy(seed.ptr + this->nonce_i.len, this->nonce_r.ptr, this->nonce_r.len);
		prf_plus = prf_plus_create(this->ike_sa->get_child_prf(this->ike_sa), seed);
		
		this->logger->log_chunk(this->logger, RAW|LEVEL2, "Rekey seed", seed);
		chunk_free(&seed);
		
		status = this->child_sa->update(this->child_sa, this->proposal, prf_plus);
		prf_plus->destroy(prf_plus);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, AUDIT, "Could not install CHILD_SA! Deleting IKE_SA");
			return DESTROY_ME;
		}
		status = this->child_sa->add_policies(this->child_sa, this->my_ts, this->other_ts);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, AUDIT, "Could not install CHILD_SA policy! Deleting IKE_SA");
			return DESTROY_ME;
		}
		this->ike_sa->add_child_sa(this->ike_sa, this->child_sa);
	}
	
	this->ike_sa->set_last_replied_message_id(this->ike_sa, response->get_message_id(response));
	
	/* create new state */
	this->ike_sa->set_new_state(this->ike_sa, (state_t*)ike_sa_established_create(this->ike_sa));
	this->public.state_interface.destroy(&this->public.state_interface);
	
	/* if we are rekeying, inform the old child SA that it has been superseeded and
	 * start its delete */
	if (this->reqid)
	{
		old_child_sa = this->ike_sa->public.get_child_sa(&this->ike_sa->public, this->reqid);
		if (old_child_sa)
		{
			old_child_sa->set_rekeyed(old_child_sa);
		}
		this->ike_sa->public.delete_child_sa(&this->ike_sa->public, this->reqid);
	}
	return SUCCESS;
}

/**
 * Implements state_t.get_state
 */
static ike_sa_state_t get_state(private_create_child_sa_requested_t *this)
{
	return CREATE_CHILD_SA_REQUESTED;
}

/**
 * Implementation of state_t.destroy.
 */
static void destroy(private_create_child_sa_requested_t *this)
{
	chunk_free(&this->nonce_i);
	chunk_free(&this->nonce_r);
	free(this);
}

/*
 * Described in header.
 */
create_child_sa_requested_t *create_child_sa_requested_create(protected_ike_sa_t *ike_sa, child_sa_t *child_sa, chunk_t nonce_i, u_int32_t reqid)
{
	private_create_child_sa_requested_t *this = malloc_thing(private_create_child_sa_requested_t);
	
	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->child_sa = child_sa;
	this->nonce_i = nonce_i;
	this->nonce_r = CHUNK_INITIALIZER;
	this->reqid = reqid;
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);
	
	return &(this->public);
}
