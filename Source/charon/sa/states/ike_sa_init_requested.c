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


typedef struct private_ike_sa_init_requested_t private_ike_sa_init_requested_t;

/**
 * Private data of a ike_sa_init_requested_t object.
 *
 */
struct private_ike_sa_init_requested_t {
	/**
	 * methods of the state_t interface
	 */
	ike_sa_init_requested_t public;
	
	/** 
	 * Assigned IKE_SA
	 */
	protected_ike_sa_t *ike_sa;
	
	/**
	 * Diffie Hellman object used to compute shared secret
	 */
	diffie_hellman_t *diffie_hellman;
	
	/**
	 * Shared secret of successful exchange
	 */
	chunk_t shared_secret;
	
	/**
	 * Sent nonce value
	 */
	chunk_t sent_nonce;
	
	/**
	 * Received nonce
	 */
	chunk_t received_nonce;
	
	/**
	 * DH group priority used to get dh_group_number from configuration manager.
	 * 
	 * Currently unused but usable if informational messages of unsupported dh group number are processed.
	 */
	u_int16_t dh_group_priority;
	
	/**
	 * Logger used to log data 
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
	
	/**
	 * Builds the IKE_SA_AUTH request message.
	 * 
	 * @param this		calling object
	 * @param message	the created message will be stored at this location
	 */
	void (*build_ike_auth_request) (private_ike_sa_init_requested_t *this, message_t **message);
	
	/**
	 * Builds the id payload for this state.
	 * 
	 * @param this		calling object
	 * @param payload	The generated payload object of type id_payload_t is 
	 * 					stored at this location.
	 */
	void (*build_id_payload) (private_ike_sa_init_requested_t *this, payload_t **payload);
	
	/**
	 * Builds the id payload for this state.
	 * 
	 * @param this		calling object
	 * @param payload	The generated payload object of type auth_payload_t is 
	 * 					stored at this location.
	 */
	void (*build_auth_payload) (private_ike_sa_init_requested_t *this, payload_t **payload);
	
	/**
	 * Builds the SA payload for this state.
	 * 
	 * @param this		calling object
	 * @param payload	The generated payload object of type sa_payload_t is 
	 * 					stored at this location.
	 */
	void (*build_sa_payload) (private_ike_sa_init_requested_t *this, payload_t **payload);
	
	/**
	 * Builds the TSi payload for this state.
	 * 
	 * @param this		calling object
	 * @param payload	The generated payload object of type ts_payload_t is 
	 * 					stored at this location.
	 */
	void (*build_tsi_payload) (private_ike_sa_init_requested_t *this, payload_t **payload);
	
	/**
	 * Builds the TSr payload for this state.
	 * 
	 * @param this		calling object
	 * @param payload	The generated payload object of type ts_payload_t is 
	 * 					stored at this location.
	 */
	void (*build_tsr_payload) (private_ike_sa_init_requested_t *this, payload_t **payload);
	
	/**
	 * Destroy function called internally of this class after state change succeeded.
	 * 
	 * This destroy function does not destroy objects which were passed to the new state.
	 * 
	 * @param this		calling object
	 */
	void (*destroy_after_state_change) (private_ike_sa_init_requested_t *this);
};

/**
 * Implements state_t.get_state
 */
static status_t process_message(private_ike_sa_init_requested_t *this, message_t *ike_sa_init_reply)
{
	ike_auth_requested_t *next_state;
	exchange_type_t	exchange_type;
	init_config_t *init_config;	
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
	exchange_type = ike_sa_init_reply->get_exchange_type(ike_sa_init_reply);
	if (exchange_type != IKE_SA_INIT)
	{
		this->logger->log(this->logger, ERROR | MORE, "Message of type %s not supported in state ike_sa_init_requested",mapping_find(exchange_type_m,exchange_type));
		return FAILED;
	}
	
	if (ike_sa_init_reply->get_request(ike_sa_init_reply))
	{
		this->logger->log(this->logger, ERROR | MORE, "Only responses of type IKE_SA_INIT supported in state ike_sa_init_requested");
		return FAILED;
	}
	
	/* parse incoming message */
	status = ike_sa_init_reply->parse_body(ike_sa_init_reply, NULL, NULL);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR | MORE, "Parsing of body returned error: %s",mapping_find(status_m,status));
		return status;	
	}
	
	/* get configuration */
	init_config = this->ike_sa->get_init_config(this->ike_sa);
	

	if (responder_spi == 0)
	{
		this->logger->log(this->logger, ERROR | MORE, "Responder SPI still zero");
		return FAILED;
	}
	/* because I am original initiator i have to update the responder SPI to the new one */	
	responder_spi = ike_sa_init_reply->get_responder_spi(ike_sa_init_reply);
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
		
		this->logger->log(this->logger, CONTROL|MORE, "Processing payload %s", mapping_find(payload_type_m, payload->get_type(payload)));
		switch (payload->get_type(payload))
		{
			case NOTIFY:
			{
				notify_payload_t *notify_payload = (notify_payload_t *) payload;
				
				
				this->logger->log(this->logger, CONTROL|MORE, "Process notify type %s for protocol %s",
								  mapping_find(notify_message_type_m, notify_payload->get_notify_message_type(notify_payload)),
								  mapping_find(protocol_id_m, notify_payload->get_protocol_id(notify_payload)));
								  
				if (notify_payload->get_protocol_id(notify_payload) != IKE)
				{
					this->logger->log(this->logger, ERROR | MORE, "Notify reply not for IKE protocol.");
					payloads->destroy(payloads);
					return FAILED;	
				}
				switch (notify_payload->get_notify_message_type(notify_payload))
				{
					case NO_PROPOSAL_CHOSEN:
					{
						this->logger->log(this->logger, ERROR, "Peer didn't choose a proposal!!!");
						payloads->destroy(payloads);
						return DELETE_ME;
					}
					case INVALID_KE_PAYLOAD:
					{
						initiator_init_t *initiator_init_state;
						u_int16_t new_dh_group_priority;
						
						this->logger->log(this->logger, ERROR, "Selected DH group is not the one in the proposal selected by the responder!");
						payloads->destroy(payloads);						
						/* Going to change state back to initiator_init_t */
						this->logger->log(this->logger, CONTROL|MOST, "Create next state object");
						initiator_init_state = initiator_init_create(this->ike_sa);

						/* buffer of sent and received messages has to get reseted */
						this->ike_sa->reset_message_buffers(this->ike_sa);

						/* state can now be changed */ 
						this->ike_sa->set_new_state(this->ike_sa,(state_t *) initiator_init_state);

						/* state has NOW changed :-) */
						this->logger->log(this->logger, CONTROL|MORE, "Changed state of IKE_SA from %s to %s", mapping_find(ike_sa_state_m,INITIATOR_INIT),mapping_find(ike_sa_state_m,IKE_SA_INIT_REQUESTED) );

						this->logger->log(this->logger, CONTROL|MOST, "Destroy old sate object");
						this->logger->log(this->logger, CONTROL|MOST, "Going to retry initialization of connection");
						new_dh_group_priority = this->dh_group_priority + 1;
						
						this->public.state_interface.destroy(&(this->public.state_interface));
						return (initiator_init_state->retry_initiate_connection (initiator_init_state,new_dh_group_priority));
					}
					default:
					{
						/*
						 * If an unrecognized Notify type is received, the IKE_SA gets destroyed.
						 * 
						 */
						
						this->logger->log(this->logger, ERROR, "Notify type %s not recognized in state ike_sa_init_requested.",
										  mapping_find(notify_message_type_m,notify_payload->get_notify_message_type(notify_payload)));
						payloads->destroy(payloads);
						return DELETE_ME;	
					}
				}
			
			/**
			 * TODO check for notify of type 
			 * 
			 * and change to state INITIATOR_INIT;
			 * 
			 * call destroy after state change not destroy_after_state_change!!!
			 */
			}
			case SECURITY_ASSOCIATION:
			{
				sa_payload_t *sa_payload = (sa_payload_t*)payload;
				ike_proposal_t *ike_proposals;
				ike_proposal_t selected_proposal;
				size_t proposal_count;			

				
				/* get the list of selected proposals */ 
				status = sa_payload->get_ike_proposals (sa_payload, &ike_proposals,&proposal_count);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR | MORE, "SA payload does not contain IKE proposals");
					payloads->destroy(payloads);
					return status;	
				}
				/* the peer has to select only one proposal */
				if (proposal_count != 1)
				{
					this->logger->log(this->logger, ERROR | MORE, "More then 1 proposal (%d) selected!",proposal_count);
					allocator_free(ike_proposals);
					payloads->destroy(payloads);
					return status;							
				}
				
				/* now let the configuration-manager check the selected proposals*/
				this->logger->log(this->logger, CONTROL | MOST, "Check selected proposal");
				status = init_config->select_proposal (init_config,ike_proposals,1,&selected_proposal);
				allocator_free(ike_proposals);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR | MORE, "Selected proposal not a suggested one! Peer is trying to trick me!");
					payloads->destroy(payloads);
					return status;
				}
							
				status = this->ike_sa->create_transforms_from_proposal(this->ike_sa,&selected_proposal);	
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR | MORE, "Transform objects could not be created from selected proposal");
					payloads->destroy(payloads);
					return status;
				}
				/* ok, we have what we need for sa_payload */
				break;
			}
			case KEY_EXCHANGE:
			{
				ke_payload_t *ke_payload = (ke_payload_t*)payload;
				this->diffie_hellman->set_other_public_value(this->diffie_hellman, ke_payload->get_key_exchange_data(ke_payload));				
				/* shared secret is computed AFTER processing of all payloads... */				
				break;
			}
			case NONCE:
			{
				nonce_payload_t *nonce_payload = (nonce_payload_t*)payload;
				
				allocator_free(this->received_nonce.ptr);

				this->received_nonce = CHUNK_INITIALIZER;
				
				nonce_payload->get_nonce(nonce_payload, &(this->received_nonce));
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR, "Payload type %s not supported in state ike_sa_init_requested!", mapping_find(payload_type_m, payload->get_type(payload)));
				payloads->destroy(payloads);
				return FAILED;
			}
				
		}
			
	}
	payloads->destroy(payloads);
	
	allocator_free(this->shared_secret.ptr);
	this->shared_secret = CHUNK_INITIALIZER;
	
	/* store shared secret  
	 * status of dh objectt does not have to get checked cause other key is set
	 */
	this->logger->log(this->logger, CONTROL | MOST, "Retrieve shared secret and store it");
	status = this->diffie_hellman->get_shared_secret(this->diffie_hellman, &(this->shared_secret));		
	this->logger->log_chunk(this->logger, PRIVATE, "Shared secret", &this->shared_secret);

	this->logger->log(this->logger, CONTROL | MOST, "Going to derive all secrets from shared secret");	
	this->ike_sa->compute_secrets(this->ike_sa,this->shared_secret,this->sent_nonce, this->received_nonce);

	/* build the complete IKE_AUTH request */
	this->build_ike_auth_request (this,&request);

	/* message can now be sent (must not be destroyed) */
	status = this->ike_sa->send_request(this->ike_sa, request);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not send request message");
		request->destroy(request);
		return DELETE_ME;
	}

	/* state can now be changed */
	this->logger->log(this->logger, CONTROL|MOST, "Create next state object");
	next_state = ike_auth_requested_create(this->ike_sa);

	/* state can now be changed */ 
	this->ike_sa->set_new_state(this->ike_sa,(state_t *) next_state);

	/* state has NOW changed :-) */
	this->logger->log(this->logger, CONTROL|MORE, "Changed state of IKE_SA from %s to %s", mapping_find(ike_sa_state_m,IKE_SA_INIT_REQUESTED),mapping_find(ike_sa_state_m,IKE_AUTH_REQUESTED) );

	this->logger->log(this->logger, CONTROL|MOST, "Destroy old sate object");
	this->destroy_after_state_change(this);
	return SUCCESS;
}

/**
 * implements private_ike_sa_init_requested_t.build_ike_auth_request
 */
static void build_ike_auth_request (private_ike_sa_init_requested_t *this, message_t **request)
{
	payload_t *payload;
	message_t *message;
	
	/* going to build message */
	this->logger->log(this->logger, CONTROL|MOST, "Going to build empty message");
	this->ike_sa->build_message(this->ike_sa, IKE_AUTH, TRUE, &message);
	
	/* build id payload */
	this->build_id_payload(this, &payload);
	this->logger->log(this->logger, CONTROL|MOST, "add ID payload to message");
	message->add_payload(message, payload);

	/* build auth payload */
	this->build_auth_payload(this, &payload);
	this->logger->log(this->logger, CONTROL|MOST, "add AUTH payload to message");
	message->add_payload(message, payload);
	
	/* build sa payload */
	this->build_sa_payload(this, &payload);
	this->logger->log(this->logger, CONTROL|MOST, "add SA payload to message");
	message->add_payload(message, payload);
	
	/* build tsi payload */
	this->build_tsi_payload(this, &payload);
	this->logger->log(this->logger, CONTROL|MOST, "add TSi payload to message");
	message->add_payload(message, payload);	
	
	/* build tsr payload */
	this->build_tsr_payload(this, &payload);
	this->logger->log(this->logger, CONTROL|MOST, "add TSr payload to message");
	message->add_payload(message, payload);	
	
	*request = message;
}

/**
 * Implementation of private_ike_sa_init_requested_t.build_id_payload.
 */
static void build_id_payload (private_ike_sa_init_requested_t *this, payload_t **payload)
{
	sa_config_t *sa_config;
	id_payload_t *id_payload;
	identification_t *identification;
	
	sa_config = this->ike_sa->get_sa_config(this->ike_sa);
	/* identification_t object gets NOT cloned here */
	identification = sa_config->get_my_id(sa_config);
	id_payload = id_payload_create_from_identification(TRUE,identification);
	
	*payload = (payload_t *) id_payload;
}

/**
 * Implementation of private_ike_sa_init_requested_t.build_auth_payload.
 */
static void build_auth_payload (private_ike_sa_init_requested_t *this, payload_t **payload)
{
	auth_payload_t *auth_payload;
	sa_config_t *sa_config;

	sa_config = this->ike_sa->get_sa_config(this->ike_sa);
	auth_payload = auth_payload_create();
	auth_payload->set_auth_method(auth_payload,sa_config->get_auth_method(sa_config));
	/*
	 * TODO generate AUTH DATA 
	 */

	*payload = (payload_t *) auth_payload;
}

/**
 * Implementation of private_ike_sa_init_requested_t.build_sa_payload.
 */
static void build_sa_payload (private_ike_sa_init_requested_t *this, payload_t **payload)
{
	child_proposal_t *proposals;
	sa_payload_t *sa_payload;
	sa_config_t *sa_config;
	size_t proposal_count;
	/*
	 * TODO: get SPIs from kernel
	 */
	u_int8_t esp_spi[4] = {0x01,0x01,0x01,0x01};
	u_int8_t ah_spi[4] = {0x01,0x01,0x01,0x01};

	sa_config = this->ike_sa->get_sa_config(this->ike_sa);
	proposal_count = sa_config->get_proposals(sa_config,ah_spi,esp_spi,&proposals);
	sa_payload = sa_payload_create_from_child_proposals(proposals, proposal_count);
	allocator_free(proposals);

	*payload = (payload_t *) sa_payload;
}

/**
 * Implementation of private_ike_sa_init_requested_t.build_tsi_payload.
 */
static void build_tsi_payload (private_ike_sa_init_requested_t *this, payload_t **payload)
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

	*payload = (payload_t *) ts_payload;
}

/**
 * Implementation of private_ike_sa_init_requested_t.build_tsr_payload.
 */
static void build_tsr_payload (private_ike_sa_init_requested_t *this, payload_t **payload)
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

	*payload = (payload_t *) ts_payload;
}


/**
 * Implements state_t.get_state
 */
static ike_sa_state_t get_state(private_ike_sa_init_requested_t *this)
{
	return IKE_SA_INIT_REQUESTED;
}

/**
 * Implements private_ike_sa_init_requested_t.destroy_after_state_change
 */
static void destroy_after_state_change (private_ike_sa_init_requested_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy state of type ike_sa_init_requested_t after state change.");
	
	this->logger->log(this->logger, CONTROL | MOST, "Destroy diffie hellman object");
	this->diffie_hellman->destroy(this->diffie_hellman);
	this->logger->log(this->logger, CONTROL | MOST, "Destroy sent nonce");	
	allocator_free(this->sent_nonce.ptr);
	this->logger->log(this->logger, CONTROL | MOST, "Destroy received nonce");
	allocator_free(this->received_nonce.ptr);
	this->logger->log(this->logger, CONTROL | MOST, "Destroy shared secret (secrets allready derived)");
	allocator_free_chunk(&(this->shared_secret));
	this->logger->log(this->logger, CONTROL | MOST, "Destroy object itself");
	allocator_free(this);	
}

/**
 * Implements state_t.get_state
 */
static void destroy(private_ike_sa_init_requested_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy state of type ike_sa_init_requested_t");
	
	this->logger->log(this->logger, CONTROL | MOST, "Destroy diffie hellman object");
	this->diffie_hellman->destroy(this->diffie_hellman);
	this->logger->log(this->logger, CONTROL | MOST, "Destroy sent nonce");	
	allocator_free(this->sent_nonce.ptr);
	this->logger->log(this->logger, CONTROL | MOST, "Destroy received nonce");
	allocator_free(this->received_nonce.ptr);
	this->logger->log(this->logger, CONTROL | MOST, "Destroy shared secret (secrets allready derived)");
	allocator_free_chunk(&(this->shared_secret));
	this->logger->log(this->logger, CONTROL | MOST, "Destroy object itself");
	allocator_free(this);
}

/* 
 * Described in header.
 */
ike_sa_init_requested_t *ike_sa_init_requested_create(protected_ike_sa_t *ike_sa, u_int16_t dh_group_priority, diffie_hellman_t *diffie_hellman, chunk_t sent_nonce)
{
	private_ike_sa_init_requested_t *this = allocator_alloc_thing(private_ike_sa_init_requested_t);
	
	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private functions */
	this->build_ike_auth_request = build_ike_auth_request;
	this->build_id_payload = build_id_payload;
	this->build_auth_payload = build_auth_payload;
	this->build_sa_payload = build_sa_payload;
	this->build_tsi_payload = build_tsi_payload;
	this->build_tsr_payload = build_tsr_payload;
	this->destroy_after_state_change = destroy_after_state_change;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->received_nonce = CHUNK_INITIALIZER;
	this->shared_secret = CHUNK_INITIALIZER;
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	this->diffie_hellman = diffie_hellman;
	this->sent_nonce = sent_nonce;
	this->dh_group_priority = dh_group_priority;
	
	return &(this->public);
}
