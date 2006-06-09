/**
 * @file ike_sa_established.c
 * 
 * @brief Implementation of ike_sa_established_t.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#include "ike_sa_established.h"

#include <daemon.h>
#include <encoding/payloads/delete_payload.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ts_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <sa/child_sa.h>
#include <sa/states/delete_ike_sa_requested.h>


typedef struct private_ike_sa_established_t private_ike_sa_established_t;

/**
 * Private data of a ike_sa_established_t object.
 */
struct private_ike_sa_established_t {
	/**
	 * methods of the state_t interface
	 */
	ike_sa_established_t public;
	
	/** 
	 * Assigned IKE_SA.
	 */
	protected_ike_sa_t *ike_sa;
	
	/**
	 * Nonce for a new child SA, chosen by initiator
	 */
	chunk_t nonce_i;
	
	/**
	 * Nonce for a new child SA, chosen by responder
	 */
	chunk_t nonce_r;
	
	/**
	 * Traffic selectors for a new child SA, responder side
	 */
	linked_list_t *my_ts;
	
	/**
	 * Traffic selectors for a new child SA, initiator side
	 */
	linked_list_t *other_ts;
	
	/**
	 * Newly set up child sa
	 */
	child_sa_t *child_sa;
	
	/** 
	 * Assigned logger. Use logger of IKE_SA.
	 */
	logger_t *logger;
};

/**
 * Implementation of private_ike_sa_established_t.build_sa_payload.
 */
static status_t build_sa_payload(private_ike_sa_established_t *this, sa_payload_t *request, message_t *response)
{
	proposal_t *proposal, *proposal_tmp;
	linked_list_t *proposal_list;
	sa_payload_t *sa_response;
	chunk_t seed;
	prf_plus_t *prf_plus;
	status_t status;
	connection_t *connection;
	policy_t *policy;
	
	/* prepare reply */
	sa_response = sa_payload_create();
	
	/* get proposals from request, and select one with ours */
	policy = this->ike_sa->get_policy(this->ike_sa);
	proposal_list = request->get_proposals(request);
	this->logger->log(this->logger, CONTROL|LEVEL1, "Selecting proposals:");
	proposal = policy->select_proposal(policy, proposal_list);
	/* list is not needed anymore */
	while (proposal_list->remove_last(proposal_list, (void**)&proposal_tmp) == SUCCESS)
	{
		proposal_tmp->destroy(proposal_tmp);
	}
	proposal_list->destroy(proposal_list);
	/* do we have a proposal? */
	if (proposal == NULL)
	{
		notify_payload_t *notify;
		this->logger->log(this->logger, AUDIT, "CREATE_CHILD_SA request did not contain any proposals we accept. "
				"Adding NO_PROPOSAL_CHOSEN notify");
		/* add NO_PROPOSAL_CHOSEN and an empty SA payload */
		notify = notify_payload_create_from_protocol_and_type(PROTO_IKE, NO_PROPOSAL_CHOSEN);
		response->add_payload(response, (payload_t*)notify);
	}
	else
	{
		/* set up child sa */
		seed = chunk_alloc(this->nonce_i.len + this->nonce_r.len);
		memcpy(seed.ptr, this->nonce_i.ptr, this->nonce_i.len);
		memcpy(seed.ptr + this->nonce_i.len, this->nonce_r.ptr, this->nonce_r.len);
		prf_plus = prf_plus_create(this->ike_sa->get_child_prf(this->ike_sa), seed);
		this->logger->log_chunk(this->logger, RAW|LEVEL2, "Rekey seed", seed);
		chunk_free(&seed);
		
		policy = this->ike_sa->get_policy(this->ike_sa);
		connection = this->ike_sa->get_connection(this->ike_sa);
		this->child_sa = child_sa_create(connection->get_my_host(connection),
										 connection->get_other_host(connection),
										 policy->get_soft_lifetime(policy),
										 policy->get_hard_lifetime(policy));
		
		status = this->child_sa->add(this->child_sa, proposal, prf_plus);
		prf_plus->destroy(prf_plus);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, AUDIT, "Could not install CHILD_SA!");
			sa_response->destroy(sa_response);
			proposal->destroy(proposal);
			return DESTROY_ME;
		}
		
		/* add proposal to sa payload */
		sa_response->add_proposal(sa_response, proposal);
		proposal->destroy(proposal);
	}
	response->add_payload(response, (payload_t*)sa_response);
	return SUCCESS;
}

/**
 * Implementation of private_ike_sa_established_t.build_ts_payload.
 */
static status_t build_ts_payload(private_ike_sa_established_t *this, bool ts_initiator, ts_payload_t *request, message_t* response)
{
	linked_list_t *ts_received, *ts_selected;
	traffic_selector_t *ts;
	status_t status = SUCCESS;
	ts_payload_t *ts_response;
	policy_t *policy;
	
	policy = this->ike_sa->get_policy(this->ike_sa);
	
	/* build a reply payload with selected traffic selectors */
	ts_received = request->get_traffic_selectors(request);
	/* select ts depending on payload type */
	if (ts_initiator)
	{
		ts_selected = policy->select_other_traffic_selectors(policy, ts_received);
		this->other_ts = ts_selected;
	}
	else
	{
		ts_selected = policy->select_my_traffic_selectors(policy, ts_received);
		this->my_ts = ts_selected;
	}
	
	ts_response = ts_payload_create_from_traffic_selectors(ts_initiator, ts_selected);
	response->add_payload(response, (payload_t*)ts_response);
	
	/* add notify if traffic selectors do not match */
	if (!ts_initiator &&
			(ts_selected->get_count(ts_selected) == 0 || this->other_ts->get_count(this->other_ts) == 0))
	{
		notify_payload_t *notify;
		
		this->logger->log(this->logger, AUDIT, "IKE_AUTH request did not contain any traffic selectors we accept. "
				"Adding TS_UNACCEPTABLE notify");
		
		notify = notify_payload_create_from_protocol_and_type(0, TS_UNACCEPTABLE);
		response->add_payload(response, (payload_t*)notify);
	}
	
	/* cleanup */
	while (ts_received->remove_last(ts_received, (void**)&ts) == SUCCESS)
	{
		ts->destroy(ts);
	}
	ts_received->destroy(ts_received);
	
	return status;
}

/**
 * Implementation of private_ike_sa_established_t.build_nonce_payload.
 */
static status_t build_nonce_payload(private_ike_sa_established_t *this, nonce_payload_t *nonce_request, message_t *response)
{
	nonce_payload_t *nonce_payload;
	randomizer_t *randomizer;
	status_t status;
	
	this->nonce_i = nonce_request->get_nonce(nonce_request);
	
	randomizer = this->ike_sa->get_randomizer(this->ike_sa);
	status = randomizer->allocate_pseudo_random_bytes(randomizer, NONCE_SIZE, &this->nonce_r);
	if (status != SUCCESS)
	{
		return status;
	}
	
	nonce_payload = nonce_payload_create();
	nonce_payload->set_nonce(nonce_payload, this->nonce_r);
	
	response->add_payload(response,(payload_t *) nonce_payload);
	
	return SUCCESS;
}

/**
 * Process a CREATE_CHILD_SA request
 */
static status_t process_create_child_sa(private_ike_sa_established_t *this, message_t *request, message_t *response)
{
	ts_payload_t *tsi_request = NULL, *tsr_request = NULL;
	sa_payload_t *sa_request = NULL;
	nonce_payload_t *nonce_request = NULL;
	notify_payload_t *notify = NULL;
	iterator_t *payloads;
	status_t status;
	child_sa_t *old_child_sa;
	
	/* iterate over incoming payloads. Message is verified, we can be sure there are the required payloads */
	payloads = request->get_payload_iterator(request);
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
				notify = (notify_payload_t*)payload;
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
		
	/* build response */
	this->ike_sa->build_message(this->ike_sa, CREATE_CHILD_SA, FALSE, &response);
	
	/* add payloads to it */
	status = build_nonce_payload(this, nonce_request, response);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}
	status = build_sa_payload(this, sa_request, response);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}
	status = build_ts_payload(this, TRUE, tsi_request, response);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}
	status = build_ts_payload(this, FALSE, tsr_request, response);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}
	
	status = this->ike_sa->send_response(this->ike_sa, response);
	/* message can now be sent (must not be destroyed) */
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "Unable to send CREATE_CHILD_SA reply. Ignored");
		response->destroy(response);
		return FAILED;
	}
	
	/* install child SA policies */
	if (!this->child_sa)
	{
		this->logger->log(this->logger, ERROR, "Proposal negotiation failed, no CHILD_SA built");
	}
	else if (this->my_ts->get_count(this->my_ts) == 0 || this->other_ts->get_count(this->other_ts) == 0)
	{
		this->logger->log(this->logger, ERROR, "Traffic selector negotiation failed, no CHILD_SA built");
		this->child_sa->destroy(this->child_sa);
		this->child_sa = NULL;
	}
	else
	{
		status = this->child_sa->add_policies(this->child_sa, this->my_ts, this->other_ts);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, AUDIT, "Could not install CHILD_SA policy!");
		}
		
		if (notify && notify->get_notify_message_type(notify) == REKEY_SA)
		{
			/* mark old child sa as rekeyed */
			old_child_sa = this->ike_sa->get_child_sa(this->ike_sa, notify->get_spi(notify));
			if (old_child_sa)
			{
				old_child_sa->set_rekeyed(old_child_sa, this->child_sa->get_reqid(this->child_sa));
			}
		}
		this->ike_sa->add_child_sa(this->ike_sa, this->child_sa);
	}
	
	return SUCCESS;
}


/**
 * Process an informational request
 */
static status_t process_informational(private_ike_sa_established_t *this, message_t *request, message_t *response)
{
	delete_payload_t *delete_request = NULL;
	iterator_t *payloads = request->get_payload_iterator(request);
	
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		
		switch (payload->get_type(payload))
		{
			case DELETE:
			{
				delete_request = (delete_payload_t *) payload;
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR|LEVEL1, "Ignoring Payload %s (%d)",
								  mapping_find(payload_type_m, payload->get_type(payload)),
								  payload->get_type(payload));
				break;
			}
		}
	}
	/* iterator can be destroyed */
	payloads->destroy(payloads);
	
	if (delete_request)
	{
		if (delete_request->get_protocol_id(delete_request) == PROTO_IKE)
		{
			this->logger->log(this->logger, CONTROL, "DELETE request for IKE_SA received");
			/* switch to delete_ike_sa_requested. This is not absolutly correct, but we
			 * allow the clean destruction of an SA only in this state. */
			this->ike_sa->set_new_state(this->ike_sa, (state_t*)delete_ike_sa_requested_create(this->ike_sa));
			this->public.state_interface.destroy(&(this->public.state_interface));
			return DESTROY_ME;
		}
		else
		{
			iterator_t *iterator;
			delete_payload_t *delete_response = delete_payload_create(delete_request->get_protocol_id(delete_request));
			iterator = delete_request->create_spi_iterator(delete_request);
			while (iterator->has_next(iterator))
			{	
				u_int32_t spi;
				iterator->current(iterator, (void**)&spi);
				this->logger->log(this->logger, CONTROL, "DELETE request for CHILD_SA with SPI 0x%x received", spi);
				spi = this->ike_sa->destroy_child_sa(this->ike_sa, spi);
				if (spi)
				{
					delete_response->add_spi(delete_response, spi);
				}
			}
			iterator->destroy(iterator);
			response->add_payload(response, (payload_t*)delete_response);
		}
	}
	
	if (this->ike_sa->send_response(this->ike_sa, response) != SUCCESS)
	{
		/* something is seriously wrong, kill connection */
		this->logger->log(this->logger, AUDIT, "Unable to send reply. Deleting IKE_SA");
		response->destroy(response);
		return DESTROY_ME;
	}
	return SUCCESS;
}

/**
 * Implements state_t.process_message
 */
static status_t process_message(private_ike_sa_established_t *this, message_t *message)
{
	ike_sa_id_t *ike_sa_id;
	message_t *response;
	crypter_t *crypter;
	signer_t *signer;
	status_t status;
	
	/* only requests are allowed, responses are handled in other state */
	if (!message->get_request(message))
	{
		this->logger->log(this->logger, ERROR|LEVEL1,
						  "Response not handled in state ike_sa_established");
		return FAILED;
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
	status = message->parse_body(message, crypter, signer);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "%s request decryption failed. Ignoring message",
						  mapping_find(exchange_type_m, message->get_exchange_type(message)));
		return status;
	}
	
	/* prepare a reply of the same type */
	this->ike_sa->build_message(this->ike_sa, message->get_exchange_type(message), FALSE, &response);
	
	/* handle the different message types in their functions */
	switch (message->get_exchange_type(message))
	{
		case INFORMATIONAL:
			status = process_informational(this, message, response);
			break;
		case CREATE_CHILD_SA:
			status = process_create_child_sa(this, message, response);
			break;
		default:
			this->logger->log(this->logger, ERROR | LEVEL1,
							  "Message of type %s not supported in state ike_sa_established",
							  mapping_find(exchange_type_m, message->get_exchange_type(message)));
			status = NOT_SUPPORTED;
	}
	/* clean up private members */
	chunk_free(&this->nonce_i);
	chunk_free(&this->nonce_r);
	return status;
}

/**
 * Implementation of state_t.get_state.
 */
static ike_sa_state_t get_state(private_ike_sa_established_t *this)
{
	return IKE_SA_ESTABLISHED;
}

/**
 * Implementation of state_t.get_state
 */
static void destroy(private_ike_sa_established_t *this)
{
	free(this);
}

/* 
 * Described in header.
 */
ike_sa_established_t *ike_sa_established_create(protected_ike_sa_t *ike_sa)
{
	private_ike_sa_established_t *this = malloc_thing(private_ike_sa_established_t);

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);
	this->nonce_i = CHUNK_INITIALIZER;
	this->nonce_r = CHUNK_INITIALIZER;
	
	return &(this->public);
}
