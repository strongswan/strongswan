/**
 * @file ike_sa_init_requested.c
 * 
 * @brief Implementation of ike_sa_init_requested_t.
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
 
#include "ike_sa_init_requested.h"

#include <daemon.h>
#include <utils/allocator.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/ts_payload.h>
#include <transforms/diffie_hellman.h>
#include <sa/states/ike_auth_requested.h>
#include <sa/states/initiator_init.h>
#include <sa/authenticator.h>


typedef struct private_ike_sa_init_requested_t private_ike_sa_init_requested_t;

/**
 * Private data of a ike_sa_init_requested_t object.
 *
 */
struct private_ike_sa_init_requested_t {
	/**
	 * Public interface of an ike_sa_init_requested_t object.
	 */
	ike_sa_init_requested_t public;
	
	/** 
	 * Assigned IKE_SA
	 */
	protected_ike_sa_t *ike_sa;
	
	/**
	 * Diffie Hellman object used to compute shared secret.
	 */
	diffie_hellman_t *diffie_hellman;
		
	/**
	 * Sent nonce value.
	 */
	chunk_t sent_nonce;
	
	/**
	 * Received nonce
	 */
	chunk_t received_nonce;
	
	/**
	 * Packet data of ike_sa_init request
	 */
	chunk_t ike_sa_init_request_data;
	
	/**
	 * DH group priority used to get dh_group_number from configuration manager.
	 * 
	 * Is passed to the next state object of type INITATOR_INIT if the selected group number 
	 * is not the same as in the peers selected proposal.
	 */
	u_int16_t dh_group_priority;
	
	/**
	 * Assigned logger
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
	

	/**
	 * Process NONCE payload of IKE_SA_INIT response.
	 * 
	 * @param this			calling object
	 * @param nonce_payload	NONCE payload to process
	 * @return				SUCCESS in any case
	 */
	status_t (*process_nonce_payload) (private_ike_sa_init_requested_t *this, nonce_payload_t *nonce_payload);

	/**
	 * Process SA payload of IKE_SA_INIT response.
	 * 
	 * @param this			calling object
	 * @param sa_payload	SA payload to process
	 * @return				
	 * 						- SUCCESS
	 * 						- FAILED
	 */
	status_t (*process_sa_payload) (private_ike_sa_init_requested_t *this, sa_payload_t *sa_payload);
	
	/**
	 * Process KE payload of IKE_SA_INIT response.
	 * 
	 * @param this			calling object
	 * @param sa_payload	KE payload to process
	 * @return				
	 * 						- SUCCESS
	 * 						- FAILED
	 */
	status_t (*process_ke_payload) (private_ike_sa_init_requested_t *this, ke_payload_t *ke_payload);

	/**
	 * Build ID payload for IKE_AUTH request.
	 * 
	 * @param this				calling object
	 * @param[out] id_payload	buildet ID payload
	 * @param response			created payload will be added to this message_t object
	 * @return
	 * 							- SUCCESS
	 * 							- FAILED
	 */
	status_t (*build_id_payload) (private_ike_sa_init_requested_t *this,id_payload_t **id_payload, message_t *response);
	
	/**
	 * Build AUTH payload for IKE_AUTH request.
	 * 
	 * @param this				calling object
	 * @param my_id_payload		buildet ID payload
	 * @param response			created payload will be added to this message_t object
	 * @return
	 * 							- SUCCESS
	 * 							- FAILED
	 */
	status_t (*build_auth_payload) (private_ike_sa_init_requested_t *this,id_payload_t *my_id_payload, message_t *response);

	/**
	 * Build SA payload for IKE_AUTH request.
	 * 
	 * @param this				calling object
	 * @param response			created payload will be added to this message_t object
	 * @return
	 * 							- SUCCESS
	 * 							- FAILED
	 */
	status_t (*build_sa_payload) (private_ike_sa_init_requested_t *this, message_t *response);
	
	/**
	 * Build TSi payload for IKE_AUTH request.
	 * 
	 * @param this				calling object
	 * @param response			created payload will be added to this message_t object
	 * @return
	 * 							- SUCCESS
	 * 							- FAILED
	 */
	status_t (*build_tsi_payload) (private_ike_sa_init_requested_t *this, message_t *response);
	
	/**
	 * Build TSr payload for IKE_AUTH request.
	 * 
	 * @param this				calling object
	 * @param response			created payload will be added to this message_t object
	 * @return
	 * 							- SUCCESS
	 * 							- FAILED
	 */
	status_t (*build_tsr_payload) (private_ike_sa_init_requested_t *this, message_t *response);
	
	/**
	 * Process a notify payload and react.
	 * 
	 * @param this				calling object
	 * @param notify_payload	notify_payload to handle
	 */
	status_t (*process_notify_payload) (private_ike_sa_init_requested_t *this, notify_payload_t *notify_payload);
	
	/**
	 * Destroy function called internally of this class after state change to 
	 * state IKE_AUTH_REQUESTED succeeded. 
	 * 
	 * In case of state change to INITIATOR_INIT the default destroy function gets called.
	 * 
	 * This destroy function does not destroy objects which were passed to the new state.
	 * 
	 * @param this		calling object
	 */
	void (*destroy_after_state_change) (private_ike_sa_init_requested_t *this);
};

/**
 * Implementation of state_t.process_message.
 */
static status_t process_message(private_ike_sa_init_requested_t *this, message_t *ike_sa_init_reply)
{
	ike_auth_requested_t *next_state;
	chunk_t ike_sa_init_reply_data;
	sa_payload_t *sa_payload = NULL;
	ke_payload_t *ke_payload = NULL;
	id_payload_t *id_payload = NULL;
	nonce_payload_t *nonce_payload = NULL;
	u_int64_t responder_spi;
	ike_sa_id_t *ike_sa_id;
	iterator_t *payloads;

	message_t *request;
	status_t status;
	
	/*
	 * In this state a reply message of type IKE_SA_INIT is expected:
	 * 
	 *   <--    HDR, SAr1, KEr, Nr, [CERTREQ]
	 * or
	 *   <--    HDR, N
	 */

	if (ike_sa_init_reply->get_exchange_type(ike_sa_init_reply) != IKE_SA_INIT)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "Message of type %s not supported in state ike_sa_init_requested",
							mapping_find(exchange_type_m,ike_sa_init_reply->get_exchange_type(ike_sa_init_reply)));
		return FAILED;
	}
	
	if (ike_sa_init_reply->get_request(ike_sa_init_reply))
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "IKE_SA_INIT requests not allowed state ike_sa_init_responded");
		return FAILED;
	}
	
	/* parse incoming message */
	status = ike_sa_init_reply->parse_body(ike_sa_init_reply, NULL, NULL);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "IKE_SA_INIT reply parsing faild. Ignoring message");
		return status;	
	}
	
	/* because we are original initiator we have to update the responder SPI to the new one */	
	responder_spi = ike_sa_init_reply->get_responder_spi(ike_sa_init_reply);
	if (responder_spi == 0)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "IKE_SA_INIT reply contained a SPI of zero");
		return FAILED;
	}
	ike_sa_id = this->ike_sa->public.get_id(&(this->ike_sa->public));
	ike_sa_id->set_responder_spi(ike_sa_id,responder_spi);
	
	/* Iterate over all payloads.
	 * 
	 * The message is allready checked for the right payload types.
	 */
	payloads = ike_sa_init_reply->get_payload_iterator(ike_sa_init_reply);
	while (payloads->has_next(payloads))
	{ 
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		
		switch (payload->get_type(payload))
		{
			case SECURITY_ASSOCIATION:
			{
				sa_payload = (sa_payload_t*)payload;
				break;
			}
			case KEY_EXCHANGE:
			{
				ke_payload = (ke_payload_t*)payload;
				break;
			}
			case NONCE:
			{
				nonce_payload = (nonce_payload_t*)payload;
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
			default:
			{
				this->logger->log(this->logger, ERROR|LEVEL1, "Ignoring payload %s (%d)", 
									mapping_find(payload_type_m, payload->get_type(payload)), payload->get_type(payload));
				break;
			}
				
		}
			
	}
	payloads->destroy(payloads);
	
	if (!(nonce_payload && sa_payload && ke_payload))
	{
		this->logger->log(this->logger, AUDIT, "IKE_SA_INIT reply did not contain all required payloads. Deleting IKE_SA");
		return DELETE_ME;
	}
	
	status = this->process_nonce_payload (this,nonce_payload);
	if (status != SUCCESS)
	{
		return status;
	}
	
	status = this->process_sa_payload (this,sa_payload);
	if (status != SUCCESS)
	{
		return status;
	}
	
	status = this->process_ke_payload (this,ke_payload);
	if (status != SUCCESS)
	{
		return status;
	}

	/*  build empty message */
	this->ike_sa->build_message(this->ike_sa, IKE_AUTH, TRUE, &request);
	
	status = this->build_id_payload(this, &id_payload,request);
	if (status != SUCCESS)
	{
		request->destroy(request);
		return status;
	}
	status = this->build_auth_payload(this,(id_payload_t *) id_payload, request);
	if (status != SUCCESS)
	{
		request->destroy(request);
		return status;
	}
	status = this->build_sa_payload(this, request);
	if (status != SUCCESS)
	{
		request->destroy(request);
		return status;
	}
	status = this->build_tsi_payload(this, request);
	if (status != SUCCESS)
	{
		request->destroy(request);
		return status;
	}
	status = this->build_tsr_payload(this, request);
	if (status != SUCCESS)
	{
		request->destroy(request);
		return status;
	}	
	
	/* message can now be sent (must not be destroyed) */
	status = this->ike_sa->send_request(this->ike_sa, request);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "Unable to send IKE_AUTH request. Deleting IKE_SA");
		request->destroy(request);
		return DELETE_ME;
	}
	
	this->ike_sa->set_last_replied_message_id(this->ike_sa,ike_sa_init_reply->get_message_id(ike_sa_init_reply));

	ike_sa_init_reply_data = ike_sa_init_reply->get_packet_data(ike_sa_init_reply);

	/* state can now be changed */
	next_state = ike_auth_requested_create(this->ike_sa,this->sent_nonce,this->received_nonce,ike_sa_init_reply_data);
	this->ike_sa->set_new_state(this->ike_sa,(state_t *) next_state);

	this->destroy_after_state_change(this);
	return SUCCESS;
}


/**
 * Implementation of private_ike_sa_init_requested_t.process_nonce_payload.
 */
status_t process_nonce_payload (private_ike_sa_init_requested_t *this, nonce_payload_t *nonce_payload)
{
	allocator_free(this->received_nonce.ptr);
	this->received_nonce = nonce_payload->get_nonce(nonce_payload);
	return SUCCESS;
}


/**
 * Implementation of private_ike_sa_init_requested_t.process_sa_payload.
 */
status_t process_sa_payload (private_ike_sa_init_requested_t *this, sa_payload_t *sa_payload)
{
	ike_proposal_t selected_proposal;
	ike_proposal_t *ike_proposals;
	init_config_t *init_config;
	size_t proposal_count;
	status_t status;
	
	init_config = this->ike_sa->get_init_config(this->ike_sa);
	
	/* get the list of selected proposals */ 
	status = sa_payload->get_ike_proposals (sa_payload, &ike_proposals,&proposal_count);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "IKE_SA_INIT response did not contain any proposals. Deleting IKE_SA");
		return DELETE_ME;	
	}
	/* the peer has to select only one proposal */
	if (proposal_count != 1)
	{
		this->logger->log(this->logger, AUDIT, "IKE_SA_INIT response contained more than one proposal. Deleting IKE_SA");
		allocator_free(ike_proposals);
		return DELETE_ME;							
	}
	
	/* now let the configuration-manager check the selected proposals*/
	this->logger->log(this->logger, CONTROL | LEVEL2, "Check selected proposal");
	status = init_config->select_proposal (init_config,ike_proposals,1,&selected_proposal);
	allocator_free(ike_proposals);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "IKE_SA_INIT response contained selected proposal we did not offer. Deleting IKE_SA");
		return DELETE_ME;
	}
				
	status = this->ike_sa->create_transforms_from_proposal(this->ike_sa,&selected_proposal);	
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "Transform objects could not be created from selected proposal. Deleting IKE_SA");
		return DELETE_ME;
	}
	return SUCCESS;
}

/**
 * Implementation of private_ike_sa_init_requested_t.process_ke_payload.
 */
status_t process_ke_payload (private_ike_sa_init_requested_t *this, ke_payload_t *ke_payload)
{
	chunk_t shared_secret;
	status_t status;
	
	this->diffie_hellman->set_other_public_value(this->diffie_hellman, ke_payload->get_key_exchange_data(ke_payload));
	
	/* store shared secret  
	 * status of dh object does not have to get checked cause other key is set
	 */
	this->logger->log(this->logger, CONTROL | LEVEL2, "Retrieve shared secret and store it");
	status = this->diffie_hellman->get_shared_secret(this->diffie_hellman, &shared_secret);		
	this->logger->log_chunk(this->logger, PRIVATE, "Shared secret", &shared_secret);

	this->logger->log(this->logger, CONTROL | LEVEL2, "Going to derive all secrets from shared secret");	
	this->ike_sa->compute_secrets(this->ike_sa,shared_secret,this->sent_nonce, this->received_nonce);
	
	allocator_free_chunk(&(shared_secret));
	
	return SUCCESS;
}

/**
 * Implementation of private_ike_sa_init_requested_t.build_id_payload.
 */
static status_t build_id_payload (private_ike_sa_init_requested_t *this,id_payload_t **id_payload, message_t *request)
{
	sa_config_t *sa_config;
	id_payload_t *new_id_payload;
	identification_t *identification;
	
	sa_config = this->ike_sa->get_sa_config(this->ike_sa);
	/* identification_t object gets NOT cloned here */
	identification = sa_config->get_my_id(sa_config);
	new_id_payload = id_payload_create_from_identification(TRUE,identification);
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Add ID payload to message");
	request->add_payload(request,(payload_t *) new_id_payload);
	
	*id_payload = new_id_payload;
	
	return SUCCESS;
}

/**
 * Implementation of private_ike_sa_init_requested_t.build_auth_payload.
 */
static status_t build_auth_payload (private_ike_sa_init_requested_t *this, id_payload_t *my_id_payload, message_t *request)
{
	authenticator_t *authenticator;
	auth_payload_t *auth_payload;
	status_t status;
	
	authenticator = authenticator_create(this->ike_sa);
	status = authenticator->compute_auth_data(authenticator,&auth_payload,this->ike_sa_init_request_data,this->received_nonce,my_id_payload,TRUE);	
	authenticator->destroy(authenticator);
	
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "Could not generate AUTH data for IKE_AUTH request. Deleting IKE_SA");
		return DELETE_ME;		
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Add AUTH payload to message");
	request->add_payload(request,(payload_t *) auth_payload);
	
	return SUCCESS;
}

/**
 * Implementation of private_ike_sa_init_requested_t.build_sa_payload.
 */
static status_t build_sa_payload (private_ike_sa_init_requested_t *this, message_t *request)
{
	linked_list_t *proposal_list;
	sa_payload_t *sa_payload;
	sa_config_t *sa_config;
	
	/* get proposals form config, add to payload */
	sa_config = this->ike_sa->get_sa_config(this->ike_sa);
	proposal_list = sa_config->get_proposals(sa_config);
	sa_payload = sa_payload_create_from_child_proposal_list(proposal_list);

	/* TODO child sa stuff */

	this->logger->log(this->logger, CONTROL|LEVEL2, "Add SA payload to message");
	request->add_payload(request,(payload_t *) sa_payload);
	
	return SUCCESS;
}

/**
 * Implementation of private_ike_sa_init_requested_t.build_tsi_payload.
 */
static status_t build_tsi_payload (private_ike_sa_init_requested_t *this, message_t *request)
{
	traffic_selector_t **traffic_selectors;
	size_t traffic_selectors_count;
	ts_payload_t *ts_payload;
	sa_config_t *sa_config;
	
	sa_config = this->ike_sa->get_sa_config(this->ike_sa);
	traffic_selectors_count = sa_config->get_traffic_selectors_initiator(sa_config,&traffic_selectors);
	ts_payload = ts_payload_create_from_traffic_selectors(TRUE,traffic_selectors, traffic_selectors_count);
	
	/* cleanup traffic selectors */
	while(traffic_selectors_count--) 
	{
		traffic_selector_t *ts = *traffic_selectors + traffic_selectors_count;
		ts->destroy(ts);
	}	
	allocator_free(traffic_selectors);
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Add TSi payload to message");
	request->add_payload(request,(payload_t *) ts_payload);
	
	return SUCCESS;
}

/**
 * Implementation of private_ike_sa_init_requested_t.build_tsr_payload.
 */
static status_t build_tsr_payload (private_ike_sa_init_requested_t *this, message_t *request)
{
	traffic_selector_t **traffic_selectors;
	size_t traffic_selectors_count;
	ts_payload_t *ts_payload;
	sa_config_t *sa_config;
	
	sa_config = this->ike_sa->get_sa_config(this->ike_sa);
	traffic_selectors_count = sa_config->get_traffic_selectors_responder(sa_config,&traffic_selectors);
	ts_payload = ts_payload_create_from_traffic_selectors(FALSE,traffic_selectors, traffic_selectors_count);
	
	/* cleanup traffic selectors */
	while(traffic_selectors_count--) 
	{
		traffic_selector_t *ts = *traffic_selectors + traffic_selectors_count;
		ts->destroy(ts);
	}	
	allocator_free(traffic_selectors);

	this->logger->log(this->logger, CONTROL|LEVEL2, "Add TSr payload to message");
	request->add_payload(request,(payload_t *) ts_payload);
	
	return SUCCESS;
}

/**
 * Implementation of private_ike_sa_init_requested_t.process_notify_payload.
 */
static status_t process_notify_payload(private_ike_sa_init_requested_t *this, notify_payload_t *notify_payload)
{
	notify_message_type_t notify_message_type = notify_payload->get_notify_message_type(notify_payload);
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "Process notify type %s for protocol %s",
						  mapping_find(notify_message_type_m, notify_message_type),
						  mapping_find(protocol_id_m, notify_payload->get_protocol_id(notify_payload)));
								  
	if (notify_payload->get_protocol_id(notify_payload) != IKE)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "Notify reply not for IKE protocol.");
		return FAILED;	
	}
	switch (notify_message_type)
	{
		case NO_PROPOSAL_CHOSEN:
		{
			this->logger->log(this->logger, AUDIT, "IKE_SA_INIT response contained a NO_PROPOSAL_CHOSEN notify. Deleting IKE_SA");
			return DELETE_ME;
		}
		case INVALID_MAJOR_VERSION:
		{
			this->logger->log(this->logger, AUDIT, "IKE_SA_INIT response contained a INVALID_MAJOR_VERSION notify. Deleting IKE_SA");
			return DELETE_ME;						
		}
		case INVALID_KE_PAYLOAD:
		{
			initiator_init_t *initiator_init_state;
			u_int16_t new_dh_group_priority;
			
			this->logger->log(this->logger, ERROR|LEVEL1, "Selected DH group is not the one in the proposal selected by the responder!");
			/* Going to change state back to initiator_init_t */
			this->logger->log(this->logger, CONTROL|LEVEL2, "Create next state object");
			initiator_init_state = initiator_init_create(this->ike_sa);

			/* buffer of sent and received messages has to get reseted */
			this->ike_sa->reset_message_buffers(this->ike_sa);

			/* state can now be changed */ 
			this->ike_sa->set_new_state(this->ike_sa,(state_t *) initiator_init_state);

			/* state has NOW changed :-) */
			this->logger->log(this->logger, CONTROL|LEVEL1, "Changed state of IKE_SA from %s to %s", 
								mapping_find(ike_sa_state_m,INITIATOR_INIT), mapping_find(ike_sa_state_m,IKE_SA_INIT_REQUESTED));

			this->logger->log(this->logger, CONTROL|LEVEL2, "Destroy old sate object");
			this->logger->log(this->logger, CONTROL|LEVEL2, "Going to retry initialization of connection");
			new_dh_group_priority = this->dh_group_priority + 1;
			
			this->public.state_interface.destroy(&(this->public.state_interface));
			if (initiator_init_state->retry_initiate_connection (initiator_init_state,new_dh_group_priority) != SUCCESS)
			{
				return DELETE_ME;
			}
			return FAILED;

		}
		default:
		{
			/*
			 * - In case of unknown error: IKE_SA gets destroyed.
			 * - In case of unknown status: logging
			 */
			if (notify_message_type < 16383)
			{
				this->logger->log(this->logger, AUDIT, "IKE_SA_INIT reply contained an unknown notify error (%d). Deleting IKE_SA",
								  notify_message_type);
				return DELETE_ME;	
			}
			else
			{
				this->logger->log(this->logger, CONTROL, "IKE_SA_INIT reply contained an unknown notify (%d), ignored.", 
									notify_message_type);
				return SUCCESS;
			}
		}
	}
}


/**
 * Implementation of state_t.get_state.
 */
static ike_sa_state_t get_state(private_ike_sa_init_requested_t *this)
{
	return IKE_SA_INIT_REQUESTED;
}

/**
 * Implementation of private_ike_sa_init_requested_t.destroy_after_state_change.
 */
static void destroy_after_state_change (private_ike_sa_init_requested_t *this)
{
	this->logger->log(this->logger, CONTROL | LEVEL3, "Going to destroy state of type ike_sa_init_requested_t after state change.");
	
	this->logger->log(this->logger, CONTROL | LEVEL3, "Destroy diffie hellman object");
	this->diffie_hellman->destroy(this->diffie_hellman);
	this->logger->log(this->logger, CONTROL | LEVEL3, "Destroy ike_sa_init_request_data");	
	allocator_free_chunk(&(this->ike_sa_init_request_data));
	this->logger->log(this->logger, CONTROL | LEVEL3, "Destroy object itself");
	allocator_free(this);	
}

/**
 * Implementation state_t.destroy.
 */
static void destroy(private_ike_sa_init_requested_t *this)
{
	this->logger->log(this->logger, CONTROL | LEVEL3, "Going to destroy state of type ike_sa_init_requested_t");
	
	this->logger->log(this->logger, CONTROL | LEVEL3, "Destroy diffie hellman object");
	this->diffie_hellman->destroy(this->diffie_hellman);
	this->logger->log(this->logger, CONTROL | LEVEL3, "Destroy sent nonce");	
	allocator_free(this->sent_nonce.ptr);
	this->logger->log(this->logger, CONTROL | LEVEL3, "Destroy received nonce");
	allocator_free(this->received_nonce.ptr);
	this->logger->log(this->logger, CONTROL | LEVEL3, "Destroy ike_sa_init_request_data");	
	allocator_free_chunk(&(this->ike_sa_init_request_data));
	this->logger->log(this->logger, CONTROL | LEVEL3, "Destroy object itself");
	allocator_free(this);
}

/* 
 * Described in header.
 */
ike_sa_init_requested_t *ike_sa_init_requested_create(protected_ike_sa_t *ike_sa, u_int16_t dh_group_priority, diffie_hellman_t *diffie_hellman, chunk_t sent_nonce,chunk_t ike_sa_init_request_data)
{
	private_ike_sa_init_requested_t *this = allocator_alloc_thing(private_ike_sa_init_requested_t);
	
	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private functions */
	this->destroy_after_state_change = destroy_after_state_change;
	this->process_nonce_payload = process_nonce_payload;
	this->process_sa_payload = process_sa_payload;
	this->process_ke_payload = process_ke_payload;
	this->build_auth_payload = build_auth_payload;
	this->build_tsi_payload = build_tsi_payload;
	this->build_tsr_payload = build_tsr_payload;
	this->build_id_payload = build_id_payload;
	this->build_sa_payload = build_sa_payload;
	this->process_notify_payload = process_notify_payload;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->received_nonce = CHUNK_INITIALIZER;
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	this->diffie_hellman = diffie_hellman;
	this->sent_nonce = sent_nonce;
	this->ike_sa_init_request_data = ike_sa_init_request_data;
	this->dh_group_priority = dh_group_priority;
	
	return &(this->public);
}
