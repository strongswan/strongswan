/**
 * @file ike_auth_requested.c
 * 
 * @brief Implementation of ike_auth_requested_t.
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
 
#include "ike_auth_requested.h"

#include <daemon.h>
#include <utils/allocator.h>
#include <encoding/payloads/ts_payload.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <transforms/signers/signer.h>
#include <transforms/crypters/crypter.h>
#include <sa/states/ike_sa_established.h>
#include <sa/authenticator.h>
#include <sa/child_sa.h>

typedef struct private_ike_auth_requested_t private_ike_auth_requested_t;

/**
 * Private data of a ike_auth_requested_t object.
 *
 */
struct private_ike_auth_requested_t {
	/**
	 * Public interface of ike_auth_requested_t.
	 */
	ike_auth_requested_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	 protected_ike_sa_t *ike_sa;
	 
	/**
	 * SA config, just a copy of the one stored in the ike_sa.
	 */
	sa_config_t *sa_config; 
	
	/**
	 * Received nonce from responder.
	 */
	chunk_t received_nonce;
	
	/**
	 * Sent nonce in IKE_SA_INIT request.
	 */
	chunk_t sent_nonce;
	
	/**
	 * IKE_SA_INIT-Request in binary form.
	 */
	chunk_t ike_sa_init_reply_data;
	
	/**
	 * Proposal to setup CHILD_SA
	 */
	proposal_t *proposal;
	
	/**
	 * Traffic selectors applicable at our site
	 */
	linked_list_t *my_ts;
	
	/**
	 * Traffic selectors applicable at remote site
	 */
	linked_list_t *other_ts;
	
	/**
	 * Child sa created in ike_sa_init_requested
	 */
	child_sa_t *child_sa;
	 
	/**
	 * Assigned Logger.
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
	
	/**
	 * Process the IDr payload (check if other id is valid)
	 * 
	 * @param this			calling object
	 * @param idr_payload	ID payload of responder
	 * @return				
	 * 						- SUCCESS
	 * 						- DELETE_ME
	 */
	status_t (*process_idr_payload) (private_ike_auth_requested_t *this, id_payload_t *idr_payload);
	
	/**
	 * Process the SA payload (check if selected proposals are valid, setup child sa)
	 * 
	 * @param this			calling object
	 * @param sa_payload	SA payload of responder
	 *
	 * 						- SUCCESS
	 * 						- DELETE_ME
	 */
	status_t (*process_sa_payload) (private_ike_auth_requested_t *this, sa_payload_t *sa_payload);
	
	/**
	 * Process the AUTH payload (check authenticity of message)
	 * 
	 * @param this				calling object
	 * @param auth_payload		AUTH payload of responder
	 * @param other_id_payload	ID payload of responder
	 *
	 * 						- SUCCESS
	 * 						- DELETE_ME
	 */
	status_t (*process_auth_payload) (private_ike_auth_requested_t *this, auth_payload_t *auth_payload, id_payload_t *other_id_payload);
	
	/**
	 * Process the TS payload (check if selected traffic selectors are valid)
	 * 
	 * @param this			calling object
	 * @param ts_initiator	TRUE if TS payload is TSi, FALSE for TSr
	 * @param ts_payload	TS payload of responder
	 *
	 * 						- SUCCESS
	 * 						- DELETE_ME
	 */
	status_t (*process_ts_payload) (private_ike_auth_requested_t *this, bool ts_initiator, ts_payload_t *ts_payload);
	
	/**
	 * Process a notify payload
	 * 
	 * @param this				calling object
	 * @param notify_payload	notify payload
	 *
	 * 						- SUCCESS
	 * 						- FAILED
	 * 						- DELETE_ME
	 */
	status_t (*process_notify_payload) (private_ike_auth_requested_t *this, notify_payload_t *notify_payload);
	
	/**
	 * Destroy function called internally of this class after state change to 
	 * state IKE_SA_ESTABLISHED succeeded. 
	 * 
	 * This destroy function does not destroy objects which were passed to the new state.
	 * 
	 * @param this		calling object
	 */
	void (*destroy_after_state_change) (private_ike_auth_requested_t *this);
};


/**
 * Implements state_t.process_message
 */
static status_t process_message(private_ike_auth_requested_t *this, message_t *ike_auth_reply)
{
	ts_payload_t *tsi_payload = NULL, *tsr_payload = NULL;
	id_payload_t *idr_payload = NULL;
	auth_payload_t *auth_payload = NULL;
	sa_payload_t *sa_payload = NULL;
	iterator_t *payloads = NULL;
	crypter_t *crypter = NULL;
	signer_t *signer = NULL;
	status_t status;
	host_t *my_host, *other_host;
	chunk_t seed;
	prf_plus_t *prf_plus;
	
	if (ike_auth_reply->get_exchange_type(ike_auth_reply) != IKE_AUTH)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "Message of type %s not supported in state ike_auth_requested",
							mapping_find(exchange_type_m,ike_auth_reply->get_exchange_type(ike_auth_reply)));
		return FAILED;
	}
	
	if (ike_auth_reply->get_request(ike_auth_reply))
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "IKE_AUTH requests not allowed state ike_sa_init_responded");
		return FAILED;
	}
	
	/* get signer for verification and crypter for decryption */
	signer = this->ike_sa->get_signer_responder(this->ike_sa);
	crypter = this->ike_sa->get_crypter_responder(this->ike_sa);
	
	/* parse incoming message */
	status = ike_auth_reply->parse_body(ike_auth_reply, crypter, signer);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "IKE_AUTH reply decryption failed. Ignoring message");
		return status;
	}
	
	this->sa_config = this->ike_sa->get_sa_config(this->ike_sa);
	
	/* we collect all payloads, which are processed later. Notify's are processed 
	 * in place, since we don't know how may are there.
	 */
	payloads = ike_auth_reply->get_payload_iterator(ike_auth_reply);
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		
		switch (payload->get_type(payload))
		{
			case AUTHENTICATION:
			{
				auth_payload = (auth_payload_t*)payload;
				break;	
			}
			case ID_RESPONDER:
			{
				idr_payload = (id_payload_t*)payload;
				break;	
			}
			case SECURITY_ASSOCIATION:
			{
				sa_payload = (sa_payload_t*)payload;
				break;
			}
			case TRAFFIC_SELECTOR_INITIATOR:
			{
				tsi_payload = (ts_payload_t*)payload;				
				break;	
			}
			case TRAFFIC_SELECTOR_RESPONDER:
			{
				tsr_payload = (ts_payload_t*)payload;
				break;	
			}
			case NOTIFY:
			{
				notify_payload_t *notify_payload = (notify_payload_t *) payload;
				/* handle the notify directly, abort if no further processing required */
				status = this->process_notify_payload(this, notify_payload);
				if (status != SUCCESS)
				{
					payloads->destroy(payloads);
					return status;
				}
			}
			case CERTIFICATE:
			{
				/* TODO handle cert payloads */
			}
			default:
			{
				this->logger->log(this->logger, ERROR|LEVEL1, "Ignoring Payload %s (%d)", 
									mapping_find(payload_type_m, payload->get_type(payload)), payload->get_type(payload));
				break;
			}
		}
	}
	/* iterator can be destroyed */
	payloads->destroy(payloads);
	
	/* check if we have all payloads */
	if (!(idr_payload && sa_payload && auth_payload && tsi_payload && tsr_payload))
	{
		this->logger->log(this->logger, AUDIT, "IKE_AUTH reply did not contain all required payloads. Deleting IKE_SA");
		return DELETE_ME;
	}

	/* process all payloads */
	status = this->process_idr_payload(this, idr_payload);
	if (status != SUCCESS)
	{
		return status;
	}
	status = this->process_sa_payload(this, sa_payload);
	if (status != SUCCESS)
	{
		return status;
	}
	status = this->process_auth_payload(this, auth_payload,idr_payload);
	if (status != SUCCESS)
	{
		return status;
	}
	status = this->process_ts_payload(this, TRUE, tsi_payload);
	if (status != SUCCESS)
	{
		return status;
	}
	status = this->process_ts_payload(this, FALSE, tsr_payload);
	if (status != SUCCESS)
	{
		return status;
	}
	
	/* install child SAs for AH and esp */
	if (!this->child_sa)
	{
		this->logger->log(this->logger, CONTROL, "No CHILD_SA requested, no CHILD_SA built");
	}
	if (!this->proposal)
	{
		this->logger->log(this->logger, CONTROL, "Proposal negotiation failed, no CHILD_SA built");
	}
	else if (this->my_ts->get_count(this->my_ts) == 0 || this->other_ts->get_count(this->other_ts) == 0)
	{
		this->logger->log(this->logger, CONTROL, "Traffic selector negotiation failed, no CHILD_SA built");
	}
	else
	{
		seed = allocator_alloc_as_chunk(this->sent_nonce.len + this->received_nonce.len);
		memcpy(seed.ptr, this->sent_nonce.ptr, this->sent_nonce.len);
		memcpy(seed.ptr + this->sent_nonce.len, this->received_nonce.ptr, this->received_nonce.len);
		prf_plus = prf_plus_create(this->ike_sa->get_child_prf(this->ike_sa), seed);
		allocator_free_chunk(&seed);
		
		status = this->child_sa->update(this->child_sa, this->proposal, prf_plus);
		prf_plus->destroy(prf_plus);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, AUDIT, "Could not install CHILD_SA! Deleting IKE_SA");
			return DELETE_ME;
		}
		status = this->child_sa->add_policy(this->child_sa, this->my_ts, this->other_ts);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, AUDIT, "Could not install CHILD_SA policy! Deleting IKE_SA");
			return DELETE_ME;
		}
		this->ike_sa->add_child_sa(this->ike_sa, this->child_sa);
	}
	
	this->ike_sa->set_last_replied_message_id(this->ike_sa,ike_auth_reply->get_message_id(ike_auth_reply));
	/* create new state */
	my_host = this->ike_sa->get_my_host(this->ike_sa);
	other_host = this->ike_sa->get_other_host(this->ike_sa);
	this->logger->log(this->logger, AUDIT, "IKE_SA established between %s - %s, authenticated peer with %s", 
						my_host->get_address(my_host), other_host->get_address(other_host),
						mapping_find(auth_method_m, auth_payload->get_auth_method(auth_payload)));
						
	this->ike_sa->create_delete_established_ike_sa_job(this->ike_sa,this->sa_config->get_ike_sa_lifetime(this->sa_config));
	this->ike_sa->set_new_state(this->ike_sa, (state_t*)ike_sa_established_create(this->ike_sa));
	this->destroy_after_state_change(this);
	return SUCCESS;
}

/**
 * Implements private_ike_auth_requested_t.process_idr_payload
 */
static status_t process_idr_payload(private_ike_auth_requested_t *this, id_payload_t *idr_payload)
{
	identification_t *other_id, *configured_other_id;
	
	other_id = idr_payload->get_identification(idr_payload);

	configured_other_id = this->sa_config->get_other_id(this->sa_config);
	if (configured_other_id)
	{
		this->logger->log(this->logger, CONTROL|LEVEL1, "configured ID: %s, ID of responder: %s",
							configured_other_id->get_string(configured_other_id),
							other_id->get_string(other_id));

		if (!other_id->equals(other_id, configured_other_id))
		{
			other_id->destroy(other_id);
			this->logger->log(this->logger, AUDIT, "IKE_AUTH reply contained a not requested ID. Deleting IKE_SA");
			return DELETE_ME;	
		}
	}
	
	other_id->destroy(other_id);
	/* TODO do we have to store other_id somewhere ? */
	return SUCCESS;
}

/**
 * Implements private_ike_auth_requested_t.process_sa_payload
 */
static status_t process_sa_payload(private_ike_auth_requested_t *this, sa_payload_t *sa_payload)
{
	proposal_t *proposal, *proposal_tmp;
	linked_list_t *proposal_list;
	
	/* get his selected proposal */
	proposal_list = sa_payload->get_proposals(sa_payload);
	/* check count of proposals */
	if (proposal_list->get_count(proposal_list) == 0)
	{
		/* no proposal? we accept this, but no child sa is built */
		this->logger->log(this->logger, AUDIT, "IKE_AUTH reply's SA_PAYLOAD didn't contain any proposals. No CHILD_SA created",
						  proposal_list->get_count(proposal_list));
		proposal_list->destroy(proposal_list);
		return SUCCESS;
	}
	if (proposal_list->get_count(proposal_list) > 1)
	{
		this->logger->log(this->logger, AUDIT, "IKE_AUTH reply's SA_PAYLOAD contained %d proposal. Deleting IKE_SA",
						  proposal_list->get_count(proposal_list));
		while (proposal_list->remove_last(proposal_list, (void**)&proposal) == SUCCESS)
		{
			proposal->destroy(proposal);
		}
		proposal_list->destroy(proposal_list);
		return DELETE_ME;
	}
	
	/* we have to re-check here if other's selection is valid */
	proposal = this->sa_config->select_proposal(this->sa_config, proposal_list);
	/* list not needed anymore */
	while (proposal_list->remove_last(proposal_list, (void**)&proposal_tmp) == SUCCESS)
	{
		proposal_tmp->destroy(proposal_tmp);
	}
	proposal_list->destroy(proposal_list);
	/* got a match? */
	if (proposal == NULL)
	{
		this->logger->log(this->logger, AUDIT, "IKE_AUTH reply contained a not offered proposal. Deleting IKE_SA");
		return DELETE_ME;
	}
	
	/* apply proposal */
	this->proposal = proposal;
	
	return SUCCESS;
}

/**
 * Implements private_ike_auth_requested_t.process_auth_payload
 */
static status_t process_auth_payload(private_ike_auth_requested_t *this, auth_payload_t *auth_payload, id_payload_t *other_id_payload)
{
	authenticator_t *authenticator;
	status_t status;
		
	authenticator = authenticator_create(this->ike_sa);
	status = authenticator->verify_auth_data(authenticator,auth_payload,this->ike_sa_init_reply_data,this->sent_nonce,other_id_payload,FALSE);
	authenticator->destroy(authenticator);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "Verification of IKE_AUTH reply failed. Deleting IKE_SA");
		return DELETE_ME;	
	}

	this->logger->log(this->logger, CONTROL|LEVEL1, "AUTH data verified successfully");
	return SUCCESS;	
}

/**
 * Implements private_ike_auth_requested_t.process_ts_payload
 */
static status_t process_ts_payload(private_ike_auth_requested_t *this, bool ts_initiator, ts_payload_t *ts_payload)
{
	linked_list_t *ts_received, *ts_selected;
	traffic_selector_t *ts;
	
	/* get ts form payload */
	ts_received = ts_payload->get_traffic_selectors(ts_payload);
	/* select ts depending on payload type */
	if (ts_initiator)
	{
		ts_selected = this->sa_config->select_my_traffic_selectors(this->sa_config, ts_received);
		this->my_ts = ts_selected;
	}
	else
	{
		ts_selected = this->sa_config->select_other_traffic_selectors(this->sa_config, ts_received);
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
 * Implements private_ike_auth_requested_t.process_notify_payload
 */
static status_t process_notify_payload(private_ike_auth_requested_t *this, notify_payload_t *notify_payload)
{
	notify_message_type_t notify_message_type = notify_payload->get_notify_message_type(notify_payload);
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "Process notify type %s for protocol %s",
							  mapping_find(notify_message_type_m, notify_message_type),
							  mapping_find(protocol_id_m, notify_payload->get_protocol_id(notify_payload)));
							  
	if (notify_payload->get_protocol_id(notify_payload) != IKE)
	{
		this->logger->log(this->logger, AUDIT, "IKE_AUTH reply contained a notify for an invalid protocol. Deleting IKE_SA");
		return DELETE_ME;
	}
	
	switch (notify_message_type)
	{
		case INVALID_SYNTAX:
		{
			this->logger->log(this->logger, AUDIT, "IKE_AUTH reply contained an INVALID_SYNTAX notify. Deleting IKE_SA");
			return DELETE_ME;	
			
		}
		case AUTHENTICATION_FAILED:
		{
			this->logger->log(this->logger, AUDIT, "IKE_AUTH reply contained an AUTHENTICATION_FAILED notify. Deleting IKE_SA");
			return DELETE_ME;	
			
		}
		case SINGLE_PAIR_REQUIRED:
		{
			this->logger->log(this->logger, AUDIT, "IKE_AUTH reply contained a SINGLE_PAIR_REQUIRED notify. Deleting IKE_SA");
			return DELETE_ME;		
		}
		default:
		{
			/*
			 * - In case of unknown error: IKE_SA gets destroyed.
			 * - In case of unknown status: logging
			 */
			
			if (notify_message_type < 16383)
			{
				this->logger->log(this->logger, AUDIT, "IKE_AUTH reply contained an unknown notify error (%d). Deleting IKE_SA",
								  notify_message_type);
				return DELETE_ME;	

			}
			else
			{
				this->logger->log(this->logger, CONTROL, "IKE_AUTH reply contained an unknown notify (%d), ignored.", 
									notify_message_type);
				return SUCCESS;
			}
		}
	}	
}

/**
 * Implements state_t.get_state
 */
static ike_sa_state_t get_state(private_ike_auth_requested_t *this)
{
	return IKE_AUTH_REQUESTED;
}

/**
 * Implements state_t.get_state
 */
static void destroy(private_ike_auth_requested_t *this)
{
	allocator_free_chunk(&(this->received_nonce));
	allocator_free_chunk(&(this->sent_nonce));
	allocator_free_chunk(&(this->ike_sa_init_reply_data));
	if (this->child_sa)
	{
		this->child_sa->destroy(this->child_sa);
	}
	if (this->my_ts)
	{
		traffic_selector_t *ts;
		while (this->my_ts->remove_last(this->my_ts, (void**)&ts) == SUCCESS)
		{
			ts->destroy(ts);
		}
		this->my_ts->destroy(this->my_ts);
	}
	if (this->other_ts)
	{
		traffic_selector_t *ts;
		while (this->other_ts->remove_last(this->other_ts, (void**)&ts) == SUCCESS)
		{
			ts->destroy(ts);
		}
		this->other_ts->destroy(this->other_ts);
	}
	if (this->proposal)
	{
		this->proposal->destroy(this->proposal);
	}
	allocator_free(this);
}
/**
 * Implements protected_ike_sa_t.destroy_after_state_change
 */
static void destroy_after_state_change(private_ike_auth_requested_t *this)
{
	allocator_free_chunk(&(this->received_nonce));
	allocator_free_chunk(&(this->sent_nonce));
	allocator_free_chunk(&(this->ike_sa_init_reply_data));
	if (this->my_ts)
	{
		traffic_selector_t *ts;
		while (this->my_ts->remove_last(this->my_ts, (void**)&ts) == SUCCESS)
		{
			ts->destroy(ts);
		}
		this->my_ts->destroy(this->my_ts);
	}
	if (this->other_ts)
	{
		traffic_selector_t *ts;
		while (this->other_ts->remove_last(this->other_ts, (void**)&ts) == SUCCESS)
		{
			ts->destroy(ts);
		}
		this->other_ts->destroy(this->other_ts);
	}
	if (this->proposal)
	{
		this->proposal->destroy(this->proposal);
	}
	allocator_free(this);
}

/* 
 * Described in header.
 */
ike_auth_requested_t *ike_auth_requested_create(protected_ike_sa_t *ike_sa,chunk_t sent_nonce,chunk_t received_nonce,chunk_t ike_sa_init_reply_data, child_sa_t *child_sa)
{
	private_ike_auth_requested_t *this = allocator_alloc_thing(private_ike_auth_requested_t);

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private functions */
	this->process_idr_payload = process_idr_payload;
	this->process_sa_payload = process_sa_payload;
	this->process_auth_payload = process_auth_payload;
	this->process_ts_payload = process_ts_payload;
	this->process_notify_payload = process_notify_payload;
	this->destroy_after_state_change = destroy_after_state_change;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->received_nonce = received_nonce;
	this->sent_nonce = sent_nonce;
	this->ike_sa_init_reply_data = ike_sa_init_reply_data;
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	this->my_ts = NULL;
	this->other_ts = NULL;
	this->proposal = NULL;
	this->child_sa = child_sa;
	
	return &(this->public);
}
