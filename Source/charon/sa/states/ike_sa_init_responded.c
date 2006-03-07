/**
 * @file ike_sa_init_responded.c
 * 
 * @brief State of a IKE_SA after responding to an IKE_SA_INIT request
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
 
#include "ike_sa_init_responded.h"

#include <daemon.h>
#include <utils/allocator.h>
#include <sa/authenticator.h>
#include <sa/child_sa.h>
#include <encoding/payloads/ts_payload.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <transforms/signers/signer.h>
#include <transforms/crypters/crypter.h>
#include <sa/states/ike_sa_established.h>


typedef struct private_ike_sa_init_responded_t private_ike_sa_init_responded_t;

/**
 * Private data of a ike_sa_init_responded_t object.
 *
 */
struct private_ike_sa_init_responded_t {
	/**
	 * Public interface of ike_sa_init_responded_t.
	 */
	ike_sa_init_responded_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	protected_ike_sa_t *ike_sa;
	
	/**
	 * Received nonce.
	 */
	chunk_t received_nonce;
	
	/**
	 * Sent nonce.
	 */
	chunk_t sent_nonce;
	
	/**
	 * Binary representation of the IKE_SA_INIT response.
	 */
	chunk_t ike_sa_init_response_data;

	/**
	 * Binary representation of the IKE_SA_INIT request.
	 */	
	chunk_t ike_sa_init_request_data;
	
	/**
	 * SA config to use.
	 */
	sa_config_t *sa_config;
	
	/**
	 * CHILD_SA, if set up
	 */
	child_sa_t *child_sa;
	
	/**
	 * Traffic selectors applicable at our site
	 */
	linked_list_t *my_ts;
	
	/**
	 * Traffic selectors applicable at remote site
	 */
	linked_list_t *other_ts;
	
	/**
	 * Assigned logger.
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
	
	/**
	 * Process received IDi and IDr payload and build IDr payload for IKE_AUTH response.
	 * 
	 * @param this			calling object
	 * @param request_idi	ID payload representing initiator
	 * @param request_idr	ID payload representing responder (May be zero)
	 * @param response		The created IDr payload is added to this message_t object
	 * @param response_idr	The created IDr payload is also written to this location
	 */
	status_t (*build_idr_payload) (private_ike_sa_init_responded_t *this,
									id_payload_t *request_idi, 
									id_payload_t *request_idr, 
									message_t *response,
									id_payload_t **response_idr);

	/**
	 * Process received SA payload and build SA payload for IKE_AUTH response.
	 * 
	 * @param this			calling object
	 * @param request		SA payload received in IKE_AUTH request
	 * @param response		The created SA payload is added to this message_t object
	 */
	status_t (*build_sa_payload) (private_ike_sa_init_responded_t *this, sa_payload_t *request, message_t *response);

	/**
	 * Process received AUTH payload and build AUTH payload for IKE_AUTH response.
	 * 
	 * @param this				calling object
	 * @param request			AUTH payload received in IKE_AUTH request
	 * @param other_id_payload	other ID payload needed to verify AUTH data
	 * @param my_id_payload		my ID payload needed to compute AUTH data
	 * @param response			The created AUTH payload is added to this message_t object
	 */
	status_t (*build_auth_payload) (private_ike_sa_init_responded_t *this, auth_payload_t *request,id_payload_t *other_id_payload,id_payload_t *my_id_payload, message_t* response);
	
	/**
	 * Process received TS payload and build TS payload for IKE_AUTH response.
	 * 
	 * @param this			calling object
	 * @param is_initiator	type of TS payload. TRUE for TSi, FALSE for TSr
	 * @param request		TS payload received in IKE_AUTH request
	 * @param response		the created TS payload is added to this message_t object
	 */
	status_t (*build_ts_payload) (private_ike_sa_init_responded_t *this, bool ts_initiator, ts_payload_t *request, message_t *response);
	
	/**
	 * Sends a IKE_AUTH reply containing a notify payload.
	 * 
	 * @param this		calling object
	 * @param notify_payload payload to process
	 * @return
	 * 					- DELETE_ME if IKE_SA should be deleted
	 * 					- SUCCSS if processed successfull
	 */
	status_t (*process_notify_payload) (private_ike_sa_init_responded_t *this, notify_payload_t* notify_payload);
	
	/**
	 * Destroy function called internally of this class after state change to 
	 * state IKE_SA_ESTABLISHED succeeded. 
	 * 
	 * This destroy function does not destroy objects which were passed to the new state.
	 * 
	 * @param this		calling object
	 */
	void (*destroy_after_state_change) (private_ike_sa_init_responded_t *this);
};

/**
 * Implements state_t.get_state
 */
static status_t process_message(private_ike_sa_init_responded_t *this, message_t *request)
{
	id_payload_t *idi_request = NULL, *idr_request = NULL,*idr_response;
	ts_payload_t *tsi_request = NULL, *tsr_request = NULL;
	auth_payload_t *auth_request = NULL;
	sa_payload_t *sa_request = NULL;
	iterator_t *payloads;
	message_t *response;
	crypter_t *crypter;
	signer_t *signer;
	status_t status;
	host_t *my_host, *other_host;
	
	
	if (request->get_exchange_type(request) != IKE_AUTH)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "Message of type %s not supported in state ike_sa_init_responded",
							mapping_find(exchange_type_m,request->get_exchange_type(request)));
		return FAILED;
	}
	
	if (!request->get_request(request))
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "IKE_AUTH responses not allowed state ike_sa_init_responded");
		return FAILED;
	}
	
	/* get signer for verification and crypter for decryption */
	signer = this->ike_sa->get_signer_initiator(this->ike_sa);
	crypter = this->ike_sa->get_crypter_initiator(this->ike_sa);
	
	status = request->parse_body(request, crypter, signer);
	if (status != SUCCESS)
	{
		if (status == NOT_SUPPORTED)
		{
			this->logger->log(this->logger, ERROR | LEVEL1, "IKE_AUTH request contains unsupported payload with critical flag set."
															"Deleting IKE_SA");
			this->ike_sa->send_notify(this->ike_sa, IKE_AUTH, UNSUPPORTED_CRITICAL_PAYLOAD, CHUNK_INITIALIZER);
			return DELETE_ME;
		}
		else
		{
			this->logger->log(this->logger, AUDIT, "IKE_AUTH request decryption faild. Ignoring message");
		}
		return status;
	}
	
	/* iterate over incoming payloads. Message is verified, we can be sure there are the required payloads */
	payloads = request->get_payload_iterator(request);
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		
		switch (payload->get_type(payload))
		{
			case ID_INITIATOR:
			{
				idi_request = (id_payload_t*)payload;
				break;	
			}
			case AUTHENTICATION:
			{
				auth_request = (auth_payload_t*)payload;
				break;	
			}
			case ID_RESPONDER:
			{
				idr_request = (id_payload_t*)payload;
				break;	
			}
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
			case NOTIFY:
			{
				notify_payload_t *notify_payload = (notify_payload_t *) payload;
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
			case CERTIFICATE_REQUEST:
			{
				/* TODO handle certrequest payloads */
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
	if (!(idi_request && sa_request && auth_request && tsi_request && tsr_request))
	{
		this->logger->log(this->logger, AUDIT, "IKE_AUTH reply did not contain all required payloads. Deleting IKE_SA");
		return DELETE_ME;
	}
		
	/* build response */
	this->ike_sa->build_message(this->ike_sa, IKE_AUTH, FALSE, &response);
	
	/* add payloads to it */
	status = this->build_idr_payload(this, idi_request, idr_request, response,&idr_response);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}
	status = this->build_auth_payload(this, auth_request,idi_request, idr_response,response);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}
	status = this->build_sa_payload(this, sa_request, response);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}
	status = this->build_ts_payload(this, TRUE, tsi_request, response);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}
	status = this->build_ts_payload(this, FALSE, tsr_request, response);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}		

	status = this->ike_sa->send_response(this->ike_sa, response);
	/* message can now be sent (must not be destroyed) */
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "Unable to send IKE_AUTH reply. Deleting IKE_SA");
		response->destroy(response);
		return DELETE_ME;
	}
	
	/* install child SA policies */
	if (!this->child_sa)
	{
		this->logger->log(this->logger, CONTROL, "Proposal negotiation failed, no CHILD_SA built");
	}
	else if (this->my_ts->get_count(this->my_ts) == 0 || this->other_ts->get_count(this->other_ts) == 0)
	{
		this->logger->log(this->logger, CONTROL, "Traffic selector negotiation failed, no CHILD_SA built");
		this->child_sa->destroy(this->child_sa);
		this->child_sa = NULL;
	}
	else
	{
		status = this->child_sa->add_policies(this->child_sa, this->my_ts, this->other_ts);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, AUDIT, "Could not install CHILD_SA policy! Deleting IKE_SA");
			return DELETE_ME;
		}
		this->ike_sa->add_child_sa(this->ike_sa, this->child_sa);
	}
	
	/* create new state */
	my_host = this->ike_sa->get_my_host(this->ike_sa);
	other_host = this->ike_sa->get_other_host(this->ike_sa);
	this->logger->log(this->logger, AUDIT, "IKE_SA established between %s - %s, authenticated peer with %s", 
						my_host->get_address(my_host), other_host->get_address(other_host),
						mapping_find(auth_method_m, auth_request->get_auth_method(auth_request)));
						
	this->ike_sa->set_new_state(this->ike_sa, (state_t*)ike_sa_established_create(this->ike_sa));
	this->destroy_after_state_change(this);

	return SUCCESS;
}

/**
 * Implementation of private_ike_sa_init_responded_t.build_idr_payload.
 */
static status_t build_idr_payload(private_ike_sa_init_responded_t *this, id_payload_t *request_idi, id_payload_t *request_idr, message_t *response,id_payload_t **response_idr)
{
	identification_t *other_id, *my_id = NULL;
	init_config_t *init_config;
	status_t status;
	id_payload_t *idr_response;
	
	other_id = request_idi->get_identification(request_idi);
	if (request_idr)
	{
		my_id = request_idr->get_identification(request_idr);
	}

	/* build new sa config */
	init_config = this->ike_sa->get_init_config(this->ike_sa);
	status = charon->configuration->get_sa_config_for_init_config_and_id(charon->configuration,init_config, other_id,my_id, &(this->sa_config));
	if (status != SUCCESS)
	{	
		if (my_id)
		{
			this->logger->log(this->logger, AUDIT, "IKE_AUTH request uses IDs %s to %s, which we have no config for", 
							other_id->get_string(other_id),my_id->get_string(my_id));
			my_id->destroy(my_id);	
		}
		else
		{
			this->logger->log(this->logger, AUDIT, "IKE_AUTH request uses ID %s, which we have no config for", 
							other_id->get_string(other_id));
		}
		other_id->destroy(other_id);
		return DELETE_ME;
	}
	
	if (my_id)
	{
		my_id->destroy(my_id);
	}
	other_id->destroy(other_id);
	
	/* get my id, if not requested */
	my_id = this->sa_config->get_my_id(this->sa_config);	
	
	/* set sa_config in ike_sa for other states */
	this->ike_sa->set_sa_config(this->ike_sa, this->sa_config);
	
	/*  build response */
	idr_response = id_payload_create_from_identification(FALSE, my_id);
	response->add_payload(response, (payload_t*)idr_response);
	*response_idr = idr_response;
	
	return SUCCESS;
}

/**
 * Implementation of private_ike_sa_init_responded_t.build_sa_payload.
 */
static status_t build_sa_payload(private_ike_sa_init_responded_t *this, sa_payload_t *request, message_t *response)
{
	proposal_t *proposal, *proposal_tmp;
	linked_list_t *proposal_list;
	sa_payload_t *sa_response;
	chunk_t seed;
	prf_plus_t *prf_plus;
	status_t status;
	
	/* get proposals from request */
	proposal_list = request->get_proposals(request);
	if (proposal_list->get_count(proposal_list) == 0)
	{
		/* if the other side did not offer any proposals, we do not create child sa's */
		this->logger->log(this->logger, AUDIT, "IKE_AUH request did not contain any proposals. No CHILD_SA created");
		sa_response = sa_payload_create();
		response->add_payload(response, (payload_t*)sa_response);
		proposal_list->destroy(proposal_list);
		return SUCCESS;
	}

	/* now select a proposal */
	this->logger->log(this->logger, CONTROL|LEVEL1, "Selecting proposals:");
	proposal = this->sa_config->select_proposal(this->sa_config, proposal_list);
	/* list is not needed anymore */
	while (proposal_list->remove_last(proposal_list, (void**)&proposal_tmp) == SUCCESS)
	{
		proposal_tmp->destroy(proposal_tmp);
	}
	proposal_list->destroy(proposal_list);
	/* do we have a proposal */
	if (proposal == NULL)
	{
		this->logger->log(this->logger, AUDIT, "IKE_AUTH request did not contain any proposals we accept. Deleting IKE_SA");
		this->ike_sa->send_notify(this->ike_sa, IKE_AUTH, NO_PROPOSAL_CHOSEN, CHUNK_INITIALIZER);
		return DELETE_ME;	
	}
	
	/* set up child sa */
	seed = allocator_alloc_as_chunk(this->received_nonce.len + this->sent_nonce.len);
	memcpy(seed.ptr, this->received_nonce.ptr, this->received_nonce.len);
	memcpy(seed.ptr + this->received_nonce.len, this->sent_nonce.ptr, this->sent_nonce.len);
	prf_plus = prf_plus_create(this->ike_sa->get_child_prf(this->ike_sa), seed);
	allocator_free_chunk(&seed);
		
	this->child_sa = child_sa_create(this->ike_sa->get_my_host(this->ike_sa),
									 this->ike_sa->get_other_host(this->ike_sa));
		
	status = this->child_sa->add(this->child_sa, proposal, prf_plus);
	prf_plus->destroy(prf_plus);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "Could not install CHILD_SA! Deleting IKE_SA");
		return DELETE_ME;
	}
	
	/* create payload with selected propsal */
	sa_response = sa_payload_create_from_proposal(proposal);
	response->add_payload(response, (payload_t*)sa_response);
	proposal->destroy(proposal);
	return SUCCESS;
}

/**
 * Implementation of private_ike_sa_init_responded_t.build_auth_payload.
 */
static status_t build_auth_payload(private_ike_sa_init_responded_t *this, auth_payload_t *auth_request,id_payload_t *other_id_payload,id_payload_t *my_id_payload, message_t* response)
{
	authenticator_t *authenticator;
	auth_payload_t *auth_reply;
	status_t status;
	
	authenticator = authenticator_create(this->ike_sa);
	status =  authenticator->verify_auth_data(authenticator,auth_request, this->ike_sa_init_request_data,this->sent_nonce,other_id_payload,TRUE);
	
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "IKE_AUTH request verification failed. Deleting IKE_SA");
		this->ike_sa->send_notify(this->ike_sa, IKE_AUTH, AUTHENTICATION_FAILED, CHUNK_INITIALIZER);
		authenticator->destroy(authenticator);
		return DELETE_ME;
	}
		
	status = authenticator->compute_auth_data(authenticator,&auth_reply, this->ike_sa_init_response_data,this->received_nonce,my_id_payload,FALSE);
	authenticator->destroy(authenticator);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "Unable to build authentication data for IKE_AUTH reply. Deleting IKE_SA");
		return DELETE_ME;
		
	}
	
	response->add_payload(response, (payload_t *)auth_reply);
	return SUCCESS;	
}

/**
 * Implementation of private_ike_sa_init_responded_t.build_ts_payload.
 */
static status_t build_ts_payload(private_ike_sa_init_responded_t *this, bool ts_initiator, ts_payload_t *request, message_t* response)
{
	linked_list_t *ts_received, *ts_selected;
	traffic_selector_t *ts;
	status_t status = SUCCESS;
	ts_payload_t *ts_response;

	/* build a reply payload with selected traffic selectors */
	ts_received = request->get_traffic_selectors(request);
	/* select ts depending on payload type */
	if (ts_initiator)
	{
		ts_selected = this->sa_config->select_other_traffic_selectors(this->sa_config, ts_received);
		this->other_ts = ts_selected;
	}
	else
	{
		ts_selected = this->sa_config->select_my_traffic_selectors(this->sa_config, ts_received);
		this->my_ts = ts_selected;
	}
	
	ts_response = ts_payload_create_from_traffic_selectors(ts_initiator, ts_selected);
	response->add_payload(response, (payload_t*)ts_response);
	
	/* cleanup */
	while (ts_received->remove_last(ts_received, (void**)&ts) == SUCCESS)
	{
		ts->destroy(ts);
	}
	ts_received->destroy(ts_received);
	
	return status;
}

static status_t process_notify_payload(private_ike_sa_init_responded_t *this, notify_payload_t *notify_payload)
{
	notify_message_type_t notify_message_type = notify_payload->get_notify_message_type(notify_payload);
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "Process notify type %s for protocol %s",
					  mapping_find(notify_message_type_m, notify_message_type),
					  mapping_find(protocol_id_m, notify_payload->get_protocol_id(notify_payload)));
					  
	switch (notify_message_type)
	{
		case SET_WINDOW_SIZE:
		/*
		 * TODO Increase window size.
		 */
		case INITIAL_CONTACT:
		/*
		 * TODO Delete existing IKE_SA's with other Identity.
		 */
		default:
		{
			this->logger->log(this->logger, AUDIT, "IKE_AUTH request contained an unknown notify (%d), ignored.", notify_message_type);
		}
	}

	return SUCCESS;	
}

/**
 * Implementation of state_t.get_state.
 */
static ike_sa_state_t get_state(private_ike_sa_init_responded_t *this)
{
	return IKE_SA_INIT_RESPONDED;
}

/**
 * Implementation of state_t.destroy.
 */
static void destroy(private_ike_sa_init_responded_t *this)
{
	allocator_free_chunk(&(this->received_nonce));
	allocator_free_chunk(&(this->sent_nonce));
	allocator_free_chunk(&(this->ike_sa_init_response_data));
	allocator_free_chunk(&(this->ike_sa_init_request_data));
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
	if (this->child_sa)
	{
		this->child_sa->destroy(this->child_sa);
	}

	allocator_free(this);
}
/**
 * Implementation of private_ike_sa_init_responded.destroy_after_state_change.
 */
static void destroy_after_state_change(private_ike_sa_init_responded_t *this)
{
	allocator_free_chunk(&(this->received_nonce));
	allocator_free_chunk(&(this->sent_nonce));
	allocator_free_chunk(&(this->ike_sa_init_response_data));
	allocator_free_chunk(&(this->ike_sa_init_request_data));
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

	allocator_free(this);
}

/* 
 * Described in header.
 */
ike_sa_init_responded_t *ike_sa_init_responded_create(protected_ike_sa_t *ike_sa, chunk_t received_nonce, chunk_t sent_nonce,chunk_t ike_sa_init_request_data, chunk_t ike_sa_init_response_data)
{
	private_ike_sa_init_responded_t *this = allocator_alloc_thing(private_ike_sa_init_responded_t);

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private functions */
	this->build_idr_payload = build_idr_payload;
	this->build_sa_payload = build_sa_payload;
	this->build_auth_payload = build_auth_payload;
	this->build_ts_payload = build_ts_payload;
	this->process_notify_payload = process_notify_payload;
	this->destroy_after_state_change = destroy_after_state_change;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->received_nonce = received_nonce;
	this->sent_nonce = sent_nonce;
	this->ike_sa_init_response_data = ike_sa_init_response_data;
	this->ike_sa_init_request_data = ike_sa_init_request_data;
	this->my_ts = NULL;
	this->other_ts = NULL;
	this->child_sa = NULL;
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	
	return &(this->public);
}
