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
	 * @param type		type of notify message
	 * @param data		data of notify message
	 */
	void (*send_notify_reply) (private_ike_sa_init_responded_t *this,notify_message_type_t type, chunk_t data);
};

/**
 * Implements state_t.get_state
 */
static status_t process_message(private_ike_sa_init_responded_t *this, message_t *request)
{
	id_payload_t *idi_request, *idr_request = NULL,*idr_response;
	ts_payload_t *tsi_request, *tsr_request;
	auth_payload_t *auth_request;
	sa_payload_t *sa_request;
	iterator_t *payloads;
	message_t *response;
	crypter_t *crypter;
	signer_t *signer;
	status_t status;


	if (request->get_exchange_type(request) != IKE_AUTH)
	{
		this->logger->log(this->logger, ERROR | MORE, "Message of type %s not supported in state ike_sa_init_responded",
							mapping_find(exchange_type_m,request->get_exchange_type(request)));
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
	
	status = request->parse_body(request, crypter, signer);
	if (status != SUCCESS)
	{
		if (status == NOT_SUPPORTED)
		{
			this->logger->log(this->logger, ERROR | MORE, "Message contains unsupported payload with critical flag set");
			/**
			 * TODO send unsupported type.
			 */
			this->send_notify_reply(this,UNSUPPORTED_CRITICAL_PAYLOAD,CHUNK_INITIALIZER);
			return DELETE_ME;
		}
		else
		{
			this->logger->log(this->logger, ERROR | MORE, "Could not parse body of request message");
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
			case CERTIFICATE:
			{
				/* TODO handle cert payloads */
				this->logger->log(this->logger, ERROR | MORE, "Payload type CERTIFICATE currently not supported and so not handled");
				break;
			}
			case CERTIFICATE_REQUEST:
			{
				/* TODO handle certrequest payloads */
				this->logger->log(this->logger, ERROR | MORE, "Payload type CERTIFICATE_REQUEST currently not supported and so not handled");
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

				this->logger->log(this->logger, CONTROL|MORE, "Process notify type %s for protocol %s",
								  mapping_find(notify_message_type_m, notify_payload->get_notify_message_type(notify_payload)),
								  mapping_find(protocol_id_m, notify_payload->get_protocol_id(notify_payload)));
								  
				if (notify_payload->get_protocol_id(notify_payload) != IKE)
				{
					this->logger->log(this->logger, ERROR | MORE, "Notify not for IKE protocol.");
					payloads->destroy(payloads);
					return DELETE_ME;	
				}
				switch (notify_payload->get_notify_message_type(notify_payload))
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
						this->logger->log(this->logger, CONTROL|MORE, "Handling of notify type %s not implemented",
										  notify_payload->get_notify_message_type(notify_payload));
					}
				}

				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR, "Payload ID %d not handled in state IKE_AUTH_RESPONDED!", payload->get_type(payload));
				break;
			}
		}
	}
	/* iterator can be destroyed */
	payloads->destroy(payloads);
		
	/* build response */
	this->ike_sa->build_message(this->ike_sa, IKE_AUTH, FALSE, &response);
	
	/* add payloads to it */
	
	status = this->build_idr_payload(this, idi_request, idr_request, response,&idr_response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Building IDr payload failed");
		response->destroy(response);
		return status;
	}
	status = this->build_sa_payload(this, sa_request, response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Building SA payload failed");
		response->destroy(response);
		return status;
	}
	status = this->build_auth_payload(this, auth_request,idi_request, idr_response,response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Building AUTH payload failed");
		response->destroy(response);
		return status;
	}
	status = this->build_ts_payload(this, TRUE, tsi_request, response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Building TSi payload failed");
		response->destroy(response);
		return status;
	}
	status = this->build_ts_payload(this, FALSE, tsr_request, response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Building TSr payload failed");
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
	status = charon->configuration_manager->get_sa_config_for_init_config_and_id(charon->configuration_manager,init_config, other_id,my_id, &(this->sa_config));
	other_id->destroy(other_id);
	if (my_id)
	{
		my_id->destroy(my_id);
	}
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not find config for %s", other_id->get_string(other_id));
		if (my_id)
		{
			my_id->destroy(my_id);	
		}
		return DELETE_ME;
	}
	
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
			this->send_notify_reply(this,NO_PROPOSAL_CHOSEN,CHUNK_INITIALIZER);
			status = DELETE_ME;	
		}
	}
	else
	{
		this->logger->log(this->logger, ERROR, "requestor's sa payload contained no proposals");
		this->send_notify_reply(this,NO_PROPOSAL_CHOSEN,CHUNK_INITIALIZER);
		status =  DELETE_ME;
	}
	
	
	allocator_free(proposal_chosen);
	allocator_free(proposals);
	
	return status;
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
		this->logger->log(this->logger, ERROR, "Verification of AUTH payload returned status %s",mapping_find(status_m,status));
		authenticator->destroy(authenticator);
		/*
		 * Send notify message of type AUTHENTICATION_FAILED 
		 */
		this->logger->log(this->logger, CONTROL | MORE, "Send notify message of type AUTHENTICATION_FAILED");
		this->send_notify_reply (this,AUTHENTICATION_FAILED,CHUNK_INITIALIZER);		
		return DELETE_ME;
	}
		

	status = authenticator->compute_auth_data(authenticator,&auth_reply, this->ike_sa_init_response_data,this->received_nonce,my_id_payload,FALSE);
	authenticator->destroy(authenticator);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not compute AUTH payload.");
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
		status = DELETE_ME;	
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
 * Implementation of of private_responder_init_t.send_notify_reply.
 */
static void send_notify_reply (private_ike_sa_init_responded_t *this,notify_message_type_t type, chunk_t data)
{
	notify_payload_t *payload;
	message_t *response;
	packet_t *packet;
	status_t status;
	
	this->logger->log(this->logger, CONTROL|MOST, "Going to build message with notify payload");
	/* set up the reply */
	this->ike_sa->build_message(this->ike_sa, IKE_AUTH, FALSE, &response);
	payload = notify_payload_create_from_protocol_and_type(IKE,type);
	if ((data.ptr != NULL) && (data.len > 0))
	{
		this->logger->log(this->logger, CONTROL|MOST, "Add Data to notify payload");
		payload->set_notification_data(payload,data);
	}
	
	this->logger->log(this->logger, CONTROL|MOST, "Add Notify payload to message");
	response->add_payload(response,(payload_t *) payload);
	
	/* generate packet */	
	this->logger->log(this->logger, CONTROL|MOST, "Gnerate packet from message");
	status = response->generate(response, NULL, NULL, &packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not generate packet from message");
		return;
	}
	
	this->logger->log(this->logger, CONTROL|MOST, "Add packet to global send queue");
	charon->send_queue->add(charon->send_queue, packet);
	this->logger->log(this->logger, CONTROL|MOST, "Destroy message");
	response->destroy(response);
}

/**
 * Implementation of state_t.get_state.
 */
static ike_sa_state_t get_state(private_ike_sa_init_responded_t *this)
{
	return IKE_SA_INIT_RESPONDED;
}

/**
 * Implementation of state_t.get_state.
 */
static void destroy(private_ike_sa_init_responded_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy ike_sa_init_responded_t state object");
	
	this->logger->log(this->logger, CONTROL | MOST, "Destroy received nonce");
	allocator_free_chunk(&(this->received_nonce));
	this->logger->log(this->logger, CONTROL | MOST, "Destroy sent nonce");
	allocator_free_chunk(&(this->sent_nonce));
	this->logger->log(this->logger, CONTROL | MOST, "Destroy IKE_SA_INIT response octets");
	allocator_free_chunk(&(this->ike_sa_init_response_data));
	this->logger->log(this->logger, CONTROL | MOST, "Destroy IKE_SA_INIT request octets");
	allocator_free_chunk(&(this->ike_sa_init_request_data));

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
	this->send_notify_reply = send_notify_reply;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->received_nonce = received_nonce;
	this->sent_nonce = sent_nonce;
	this->ike_sa_init_response_data = ike_sa_init_response_data;
	this->ike_sa_init_request_data = ike_sa_init_request_data;
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	
	return &(this->public);
}
