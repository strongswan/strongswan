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
#include <encoding/payloads/ts_payload.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/auth_payload.h>
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
	 * methods of the state_t interface
	 */
	ike_sa_init_responded_t public;
	
	/**
	 * Assigned IKE_SA
	 */
	protected_ike_sa_t *ike_sa;
	
	/**
	 * sa config to use
	 */
	sa_config_t *sa_config;
	
	/**
	 * Logger used to log data 
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
	
	status_t (*build_idr_payload) (private_ike_sa_init_responded_t *this, id_payload_t *request_idi, id_payload_t *request_idr, message_t *response);
	status_t (*build_sa_payload) (private_ike_sa_init_responded_t *this, sa_payload_t *request, message_t *response);
	status_t (*build_auth_payload) (private_ike_sa_init_responded_t *this, auth_payload_t *request, message_t *response);
	status_t (*build_ts_payload) (private_ike_sa_init_responded_t *this, bool ts_initiator, ts_payload_t *request, message_t *response);
};

/**
 * Implements state_t.get_state
 */
static status_t process_message(private_ike_sa_init_responded_t *this, message_t *request)
{
	status_t status;
	signer_t *signer;
	crypter_t *crypter;
	iterator_t *payloads;
	exchange_type_t exchange_type;
	id_payload_t *idi_request, *idr_request = NULL;
	auth_payload_t *auth_request;
	sa_payload_t *sa_request;
	ts_payload_t *tsi_request, *tsr_request;
	message_t *response;

	exchange_type = request->get_exchange_type(request);
	if (exchange_type != IKE_AUTH)
	{
		this->logger->log(this->logger, ERROR | MORE, "Message of type %s not supported in state ike_sa_init_responded",
							mapping_find(exchange_type_m,exchange_type));
		return FAILED;
	}
	
	if (!request->get_request(request))
	{
		this->logger->log(this->logger, ERROR | MORE, "Only requests of type IKE_AUTH supported in state ike_sa_init_responded");
		return FAILED;
	}
	
	/* get signer for verification and crypter for decryption */
	signer = this->ike_sa->get_signer_initiator(this->ike_sa);
	crypter = this->ike_sa->get_crypter_initiator(this->ike_sa);
	
	/* parse incoming message */

	status = request->parse_body(request, crypter, signer);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR | MORE, "Could not parse body of request message");
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
			case CERTIFICATE:
			{
				/* TODO handle cert payloads */
				break;
			}
			case CERTIFICATE_REQUEST:
			{
				/* TODO handle certrequest payloads */
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
			default:
			{
				this->logger->log(this->logger, ERROR, "Payload type %s not supported in state ike_auth_requested!", mapping_find(payload_type_m, payload->get_type(payload)));
				payloads->destroy(payloads);
				return FAILED;
			}
		}
	}
	/* iterator can be destroyed */
	payloads->destroy(payloads);
	
	/* build response */
	this->ike_sa->build_message(this->ike_sa, IKE_AUTH, FALSE, &response);
	
	/* add payloads to it */
	
	status = this->build_idr_payload(this, idi_request, idr_request, response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Building idr payload failed");
		response->destroy(response);
		return status;
	}
	status = this->build_sa_payload(this, sa_request, response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Building sa payload failed");
		response->destroy(response);
		return status;
	}
	status = this->build_auth_payload(this, auth_request, response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Building auth payload failed");
		response->destroy(response);
		return status;
	}
	status = this->build_ts_payload(this, TRUE, tsi_request, response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Building tsi payload failed");
		response->destroy(response);
		return status;
	}
	status = this->build_ts_payload(this, FALSE, tsr_request, response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Building tsr payload failed");
		response->destroy(response);
		return status;
	}		

	this->logger->log(this->logger, CONTROL | MORE, "IKE_AUTH request successfully handled. Sending reply.");
	status = this->ike_sa->send_response(this->ike_sa, response);

	/* message can now be sent (must not be destroyed) */
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not send response message");
		response->destroy(response);
		return DELETE_ME;
	}
	
	/* create new state */
	this->ike_sa->set_new_state(this->ike_sa, (state_t*)ike_sa_established_create(this->ike_sa));
	
	this->public.state_interface.destroy(&(this->public.state_interface));

	return SUCCESS;
}

/**
 * Implements private_ike_sa_init_responded_t.build_idr_payload
 */
static status_t build_idr_payload(private_ike_sa_init_responded_t *this, id_payload_t *request_idi, id_payload_t *request_idr, message_t *response)
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
	status = charon->configuration_manager->get_sa_config_for_init_config_and_id(charon->configuration_manager,init_config, other_id,my_id, &(this->sa_config));
	other_id->destroy(other_id);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not find config for %s", other_id->get_string(other_id));
		if (my_id)
		{
			my_id->destroy(my_id);	
		}
		return NOT_FOUND;
	}
	
	/* get my id, if not requested */
	if (!my_id)
	{
		my_id = this->sa_config->get_my_id(this->sa_config);
	}
	
	/* set sa_config in ike_sa for other states */
	this->ike_sa->set_sa_config(this->ike_sa, this->sa_config);
	
	/*  build response */
	idr_response = id_payload_create_from_identification(FALSE, my_id);
	response->add_payload(response, (payload_t*)idr_response);
	
	my_id->destroy(my_id);	
	return SUCCESS;
}

/**
 * Implements private_ike_sa_init_responded_t.build_sa_payload
 */
static status_t build_sa_payload(private_ike_sa_init_responded_t *this, sa_payload_t *request, message_t *response)
{
	child_proposal_t *proposals, *proposal_chosen;
	size_t proposal_count;
	status_t status;
	sa_payload_t *sa_response;
	
	/* dummy spis, until we have a child sa to request them */
	u_int8_t ah_spi[4] = {0x01, 0x02, 0x03, 0x04};
	u_int8_t esp_spi[4] = {0x05, 0x06, 0x07, 0x08};
	
	status = request->get_child_proposals(request, &proposals, &proposal_count);
	if (status == SUCCESS)
	{
		proposal_chosen = this->sa_config->select_proposal(this->sa_config, ah_spi, esp_spi, proposals, proposal_count);
		if (proposal_chosen != NULL)
		{
			sa_response = sa_payload_create_from_child_proposals(proposal_chosen, 1);
			response->add_payload(response, (payload_t*)sa_response);
		}
		else
		{
			this->logger->log(this->logger, ERROR, "no matching proposal found");
			status = NOT_FOUND;	
		}
	}
	else
	{
		this->logger->log(this->logger, ERROR, "requestor's sa payload contained no proposals");
		status =  NOT_FOUND;
	}
	
	
	allocator_free(proposal_chosen);
	allocator_free(proposals);
	
	
	return status;
}

/**
 * Implements private_ike_sa_init_responded_t.build_auth_payload
 */
static status_t build_auth_payload(private_ike_sa_init_responded_t *this, auth_payload_t *request, message_t *response)
{
	auth_payload_t *dummy;
	u_int8_t data[] = {0x01,0x03,0x01,0x03,0x01,0x03,0x01,0x03,0x01,0x03,0x01,0x03,0x01,0x03,0x01,0x03};
	chunk_t auth_data;
	auth_data.ptr = data;
	auth_data.len = sizeof(data);
	
	/* TODO VERIFY auth here */
	
	dummy = auth_payload_create();
	dummy->set_data(dummy, auth_data);
	dummy->set_auth_method(dummy, RSA_DIGITAL_SIGNATURE);
	
	/* TODO replace dummy */
	
	response->add_payload(response, (payload_t *)dummy);
	return SUCCESS;	
}

/**
 * Implements private_ike_sa_init_responded_t.build_ts_payload
 */
static status_t build_ts_payload(private_ike_sa_init_responded_t *this, bool ts_initiator, ts_payload_t *request, message_t* response)
{
	traffic_selector_t **ts_received, **ts_selected;
	size_t ts_received_count, ts_selected_count;
	status_t status = SUCCESS;
	ts_payload_t *ts_response;

	/* build a reply payload with selected traffic selectors */
	ts_received_count = request->get_traffic_selectors(request, &ts_received);
	/* select ts depending on payload type */
	if (ts_initiator)
	{
		ts_selected_count = this->sa_config->select_traffic_selectors_initiator(this->sa_config, ts_received, ts_received_count, &ts_selected);
	}
	else
	{
		ts_selected_count = this->sa_config->select_traffic_selectors_responder(this->sa_config, ts_received, ts_received_count, &ts_selected);
	}
	if(ts_selected_count == 0)
	{
		status = NOT_FOUND;	
	}
	else
	{
		ts_response = ts_payload_create_from_traffic_selectors(ts_initiator, ts_selected, ts_selected_count);
		response->add_payload(response, (payload_t*)ts_response);
	}
	
	/* cleanup */
	while(ts_received_count--) 
	{
		traffic_selector_t *ts = *ts_received + ts_received_count;
		ts->destroy(ts);
	}
	allocator_free(ts_received);
	while(ts_selected_count--) 
	{
		traffic_selector_t *ts = *ts_selected + ts_selected_count;
		ts->destroy(ts);
	}
	allocator_free(ts_selected);
	return status;
}

/**
 * Implements state_t.get_state
 */
static ike_sa_state_t get_state(private_ike_sa_init_responded_t *this)
{
	return IKE_SA_INIT_RESPONDED;
}

/**
 * Implements state_t.get_state
 */
static void destroy(private_ike_sa_init_responded_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy ike_sa_init_responded_t state object");
		
	allocator_free(this);
}

/* 
 * Described in header.
 */
ike_sa_init_responded_t *ike_sa_init_responded_create(protected_ike_sa_t *ike_sa)
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
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	
	return &(this->public);
}
