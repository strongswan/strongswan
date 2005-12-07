/**
 * @file responder_init.c
 * 
 * @brief Implementation of responder_init_t.
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
 
#include "responder_init.h"

#include <daemon.h>
#include <sa/states/state.h>
#include <sa/states/ike_sa_init_responded.h>
#include <utils/allocator.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <transforms/diffie_hellman.h>


typedef struct private_responder_init_t private_responder_init_t;

/**
 * Private data of a responder_init_t object.
 *
 */
struct private_responder_init_t {
	/**
	 * Methods of the state_t interface.
	 */
	responder_init_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	protected_ike_sa_t *ike_sa;
	
	/**
	 * Diffie Hellman object used to compute shared secret.
	 */
	diffie_hellman_t *diffie_hellman;
		
	/**
	 * Diffie Hellman group number from selected IKE proposal.
	 */
	u_int16_t dh_group_number;	
	
	/**
	 * Priority used to get matching dh_group number.
	 */
	u_int16_t dh_group_priority;

	/**
	 * Sent nonce value.
	 * 
	 * This value is passed to the next state of type IKE_SA_INIT_RESPONDED.
	 */
	chunk_t sent_nonce;
	
	/**
	 * Received nonce value
	 * 
	 * This value is passed to the next state of type IKE_SA_INIT_RESPONDED.
	 */
	chunk_t received_nonce;
	
	/**
	 * Logger used to log data .
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
	
	/**
	 * Handles received SA payload and builds the SA payload for the response.
	 * 
	 * @param this			calling object
	 * @param sa_request	The received SA payload
	 * @param response		the SA payload is added to this response message_t object.
	 * @return
	 * 						- DELETE_ME
	 * 						- SUCCESS
	 */
	status_t (*build_sa_payload) (private_responder_init_t *this,sa_payload_t *sa_request, message_t *response);

	/**
	 * Handles received KE payload and builds the KE payload for the response.
	 * 
	 * @param this		calling object
	 * @param ke_request	The received KE payload
	 * @param response		the KE payload is added to this response message_t object.
	 * 						- DELETE_ME
	 * 						- SUCCESS
	 */
	status_t (*build_ke_payload) (private_responder_init_t *this,ke_payload_t *ke_request, message_t *response);
	
	/**
	 * Handles received NONCE payload and builds the NONCE payload for the response.
	 * 
	 * @param this			calling object
	 * @param nonce_request	The received NONCE payload
	 * @param response		the NONCE payload is added to this response message_t object.
	 * 						- DELETE_ME
	 * 						- SUCCESS
	 */
	status_t (*build_nonce_payload) (private_responder_init_t *this,nonce_payload_t *nonce_request, message_t *response);	
	
	/**
	 * Destroy function called internally of this class after change 
	 * to state IKE_SA_INIT_RESPONDED succeeded.
	 * 
	 * This destroy function does not destroy objects which were passed to the new state.
	 * 
	 * @param this		calling object
	 */
	void (*destroy_after_state_change) (private_responder_init_t *this);
	
	/**
	 * Sends a IKE_SA_INIT reply containing a notify payload.
	 * 
	 * @param this		calling object
	 * @param type		type of notify message
	 * @param data		data of notify message
	 */
	void (*send_notify_reply) (private_responder_init_t *this,notify_message_type_t type, chunk_t data);

};

/**
 * Implementation of state_t.process_message.
 */
static status_t process_message(private_responder_init_t *this, message_t *message)
{
	ike_sa_init_responded_t *next_state;
	chunk_t ike_sa_init_response_data;
	chunk_t ike_sa_init_request_data;
	nonce_payload_t *nonce_request;
	host_t *source, *destination;
	init_config_t *init_config;
	sa_payload_t *sa_request;
	ke_payload_t *ke_request;
	chunk_t shared_secret;
	iterator_t *payloads;
	message_t *response;
	status_t status;

	if (message->get_exchange_type(message) != IKE_SA_INIT)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "Message of type %s not supported in state responder_init",mapping_find(exchange_type_m,message->get_exchange_type(message)));
		return DELETE_ME;
	}
	if (!message->get_request(message))
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "Only requests of type IKE_SA_INIT supported in state responder_init");
		return DELETE_ME;
	}
	
	/* this is the first message to process, so get host infos */
	source = message->get_source(message);
	destination = message->get_destination(message);

	status = charon->configuration_manager->get_init_config_for_host(charon->configuration_manager,destination,source,&init_config);
	if (status != SUCCESS)
	{
		/* no configuration matches given host */
		this->logger->log(this->logger, ERROR | LEVEL1, "No INIT configuration found for given remote and local hosts");
		this->send_notify_reply(this,NO_PROPOSAL_CHOSEN,CHUNK_INITIALIZER);
		return DELETE_ME;
	}
	this->ike_sa->set_init_config(this->ike_sa,init_config);
	
	this->ike_sa->set_my_host(this->ike_sa, destination->clone(destination));
	this->ike_sa->set_other_host(this->ike_sa, source->clone(source));
	
	/* parse incoming message */
	status = message->parse_body(message, NULL, NULL);
	if (status != SUCCESS)
	{
		if (status == NOT_SUPPORTED)
		{
			this->logger->log(this->logger, ERROR | LEVEL1, "Message contains unsupported payload with critical flag set");
			/**
			 * TODO send unsupported type.
			 */
			this->send_notify_reply(this,UNSUPPORTED_CRITICAL_PAYLOAD,CHUNK_INITIALIZER);
		}
		else
		{
			this->logger->log(this->logger, ERROR | LEVEL1, "Could not parse body of request message");
		}
		return DELETE_ME;
	}

	payloads = message->get_payload_iterator(message);	
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
			case KEY_EXCHANGE:
			{
				ke_request = (ke_payload_t*)payload;
				break;
			}
			case NONCE:
			{
				nonce_request = (nonce_payload_t*)payload;
				break;
			}
			case NOTIFY:
			{
				notify_payload_t *notify_payload = (notify_payload_t *) payload;
				this->logger->log(this->logger, CONTROL|LEVEL1, "Process notify type %s for protocol %s",
								  mapping_find(notify_message_type_m, notify_payload->get_notify_message_type(notify_payload)),
								  mapping_find(protocol_id_m, notify_payload->get_protocol_id(notify_payload)));
								  
				if (notify_payload->get_protocol_id(notify_payload) != IKE)
				{
					this->logger->log(this->logger, ERROR | LEVEL1, "Notify not for IKE protocol.");
					payloads->destroy(payloads);
					return DELETE_ME;	
				}
				switch (notify_payload->get_notify_message_type(notify_payload))
				{
					default:
					{
						this->logger->log(this->logger, CONTROL|LEVEL1, "Processing of notify type %s not yet implemented",
											mapping_find(notify_message_type_m, notify_payload->get_notify_message_type(notify_payload)));
						break;
					}
				}
			}
			default:
			{
				this->logger->log(this->logger, CONTROL | LEVEL1, "Processing of Payload with Type number %d not implemented",payload->get_type(payload));
				break;
			}
		}
	}
	payloads->destroy(payloads);
	
	this->logger->log(this->logger, CONTROL | LEVEL1, "Going to process received payloads");
	this->ike_sa->build_message(this->ike_sa, IKE_SA_INIT, FALSE, &response);
	
	status = this->build_sa_payload(this, sa_request, response);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}
	
	status = this->build_ke_payload(this, ke_request, response);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}
	
	status = this->build_nonce_payload(this, nonce_request, response);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;
	}
	
	/* store shared secret  */
	this->logger->log(this->logger, CONTROL | LEVEL2, "Retrieve shared secret and store it");
	status = this->diffie_hellman->get_shared_secret(this->diffie_hellman, &shared_secret);
	this->logger->log_chunk(this->logger, PRIVATE, "Shared Diffie Hellman secret", &shared_secret);

	this->ike_sa->compute_secrets(this->ike_sa,shared_secret,this->received_nonce, this->sent_nonce);

	/* not used anymore */
	allocator_free_chunk(&shared_secret);
	
	/* message can now be sent (must not be destroyed) */
	status = this->ike_sa->send_response(this->ike_sa, response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not send response message");
		response->destroy(response);
		return DELETE_ME;
	}

	/* state can now be changed */
	this->logger->log(this->logger, CONTROL|LEVEL2, "Create next state object of type IKE_SA_INIT_RESPONDED");

	response = this->ike_sa->get_last_responded_message(this->ike_sa);
	ike_sa_init_response_data = response->get_packet_data(response);
	ike_sa_init_request_data = message->get_packet_data(message);

	next_state = ike_sa_init_responded_create(this->ike_sa, this->received_nonce, this->sent_nonce,ike_sa_init_request_data,ike_sa_init_response_data);
	
	/* state can now be changed */
	this->ike_sa->set_new_state(this->ike_sa, (state_t *) next_state);
	/* state has NOW changed :-) */
	this->logger->log(this->logger, CONTROL|LEVEL1, "Changed state of IKE_SA from %s to %s",mapping_find(ike_sa_state_m,RESPONDER_INIT),mapping_find(ike_sa_state_m,IKE_SA_INIT_RESPONDED) );

	this->logger->log(this->logger, CONTROL|LEVEL2, "Destroy old sate object");
	this->destroy_after_state_change(this);	
	
	return SUCCESS;
}

/**
 * Implementation of private_initiator_init_t.build_sa_payload.
 */
static status_t build_sa_payload(private_responder_init_t *this,sa_payload_t *sa_request, message_t *response)
{
	ike_proposal_t selected_proposal;
	ike_proposal_t *ike_proposals;
	init_config_t *init_config;
	sa_payload_t* sa_payload;
	size_t proposal_count;
	status_t status;

	init_config = this->ike_sa->get_init_config(this->ike_sa);

	this->logger->log(this->logger, CONTROL | LEVEL2, "Process received SA payload");
	/* get the list of suggested proposals */ 
	status = sa_request->get_ike_proposals (sa_request, &ike_proposals,&proposal_count);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "SA payload does not contain IKE proposals");
		this->send_notify_reply(this,NO_PROPOSAL_CHOSEN,CHUNK_INITIALIZER);
		return DELETE_ME;	
	}

	status = init_config->select_proposal(init_config, ike_proposals,proposal_count,&(selected_proposal));
	allocator_free(ike_proposals);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "No proposal of suggested proposals selected");
		this->send_notify_reply(this,NO_PROPOSAL_CHOSEN,CHUNK_INITIALIZER);
		return DELETE_ME;
	}
	
	this->dh_group_number = selected_proposal.diffie_hellman_group;
	
	status = this->ike_sa->create_transforms_from_proposal(this->ike_sa,&(selected_proposal));	
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "Transform objects could not be created from selected proposal");
		return DELETE_ME;
	}
	
	this->logger->log(this->logger, CONTROL | LEVEL2, "SA Payload processed");
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Building SA payload");
	sa_payload = sa_payload_create_from_ike_proposals(&(selected_proposal),1);	
	this->logger->log(this->logger, CONTROL|LEVEL2, "add SA payload to message");
	response->add_payload(response,(payload_t *) sa_payload);
	
	return SUCCESS;
}

/**
 * Implementation of private_initiator_init_t.build_ke_payload.
 */
static status_t build_ke_payload(private_responder_init_t *this,ke_payload_t *ke_request, message_t *response)
{
	diffie_hellman_group_t group;
	ke_payload_t *ke_payload;
	diffie_hellman_t *dh;
	chunk_t key_data;
				
	this->logger->log(this->logger, CONTROL | LEVEL2, "Process received KE payload");
	group = ke_request->get_dh_group_number(ke_request);
				
	if (group == MODP_UNDEFINED)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "Diffie hellman group set to undefined!");
		return DELETE_ME;
	}
	if (this->dh_group_number != group)
	{
		u_int16_t accepted_group;
		chunk_t accepted_group_chunk;
		/* group not same as selected one 
		 * Maybe key exchange payload is before SA payload */
		this->logger->log(this->logger, ERROR | LEVEL1, "Diffie hellman group not as in selected proposal!");
		
		accepted_group = htons(this->dh_group_number);
		accepted_group_chunk.ptr = (u_int8_t*) &(accepted_group);
		accepted_group_chunk.len = 2;
		this->send_notify_reply(this,INVALID_KE_PAYLOAD,accepted_group_chunk);
		return DELETE_ME;
	}
			
	/* create diffie hellman object to handle DH exchange */
	dh = diffie_hellman_create(group);
	if (dh == NULL)
	{
		this->logger->log(this->logger, ERROR, "Could not generate DH object with group %d",mapping_find(diffie_hellman_group_m,group) );
		return DELETE_ME;
	}
	this->logger->log(this->logger, CONTROL | LEVEL2, "Set other DH public value");
	
	dh->set_other_public_value(dh, ke_request->get_key_exchange_data(ke_request));

	this->diffie_hellman = dh;
	
	this->logger->log(this->logger, CONTROL | LEVEL2, "KE Payload processed.");

	this->logger->log(this->logger, CONTROL|LEVEL2, "Building KE payload");
	this->diffie_hellman->get_my_public_value(this->diffie_hellman,&key_data);

	ke_payload = ke_payload_create();
	ke_payload->set_key_exchange_data(ke_payload,key_data);
	ke_payload->set_dh_group_number(ke_payload, this->dh_group_number);
	allocator_free_chunk(&key_data);

	this->logger->log(this->logger, CONTROL|LEVEL2, "Add KE payload to message");
	response->add_payload(response,(payload_t *) ke_payload);
	
	return SUCCESS;
}

/**
 * Implementation of private_initiator_init_t.build_nonce_payload.
 */
static status_t build_nonce_payload(private_responder_init_t *this,nonce_payload_t *nonce_request, message_t *response)
{
	nonce_payload_t *nonce_payload;
	randomizer_t *randomizer;

	this->logger->log(this->logger, CONTROL | LEVEL2, "Process received NONCE payload");
	allocator_free(this->received_nonce.ptr);
	this->received_nonce = CHUNK_INITIALIZER;

	this->logger->log(this->logger, CONTROL | LEVEL2, "Get NONCE value and store it");
	this->received_nonce = nonce_request->get_nonce(nonce_request);
	
	this->logger->log(this->logger, CONTROL | LEVEL2, "Create new NONCE value.");	
	
	randomizer = this->ike_sa->get_randomizer(this->ike_sa);
	randomizer->allocate_pseudo_random_bytes(randomizer, NONCE_SIZE, &(this->sent_nonce));
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Building NONCE payload");
	nonce_payload = nonce_payload_create();
	nonce_payload->set_nonce(nonce_payload, this->sent_nonce);
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Add NONCE payload to message");
	response->add_payload(response,(payload_t *) nonce_payload);
	
	return SUCCESS;
}


/**
 * Implementation of  state_t.get_state.
 */
static ike_sa_state_t get_state(private_responder_init_t *this)
{
	return RESPONDER_INIT;
}

/**
 * Implementation of private_initiator_init_t.send_notify_reply.
 */
static void send_notify_reply (private_responder_init_t *this,notify_message_type_t type, chunk_t data)
{
	notify_payload_t *payload;
	message_t *response;
	packet_t *packet;
	status_t status;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Going to build message with notify payload");
	/* set up the reply */
	this->ike_sa->build_message(this->ike_sa, IKE_SA_INIT, FALSE, &response);
	payload = notify_payload_create_from_protocol_and_type(IKE,type);
	if ((data.ptr != NULL) && (data.len > 0))
	{
		this->logger->log(this->logger, CONTROL|LEVEL2, "Add Data to notify payload");
		payload->set_notification_data(payload,data);
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Add Notify payload to message");
	response->add_payload(response,(payload_t *) payload);
	
	/* generate packet */	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Gnerate packet from message");
	status = response->generate(response, NULL, NULL, &packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not generate packet from message");
		return;
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Add packet to global send queue");
	charon->send_queue->add(charon->send_queue, packet);
	this->logger->log(this->logger, CONTROL|LEVEL2, "Destroy message");
	response->destroy(response);
}

/**
 * Implementation of state_t.destroy.
 */
static void destroy(private_responder_init_t *this)
{
	this->logger->log(this->logger, CONTROL | LEVEL1, "Going to destroy responder init state object");
	
	this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy sent nonce");
	allocator_free_chunk(&(this->sent_nonce));
	this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy received nonce");
	allocator_free_chunk(&(this->received_nonce));

	if (this->diffie_hellman != NULL)
	{
		this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy diffie_hellman_t hellman object");
		this->diffie_hellman->destroy(this->diffie_hellman);
	}
	this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy object");
	allocator_free(this);
}

/**
 * Implementation of private_responder_init_t.destroy_after_state_change
 */
static void destroy_after_state_change (private_responder_init_t *this)
{
	this->logger->log(this->logger, CONTROL | LEVEL1, "Going to destroy responder_init_t state object");
	
	/* destroy diffie hellman object */
	if (this->diffie_hellman != NULL)
	{
		this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy diffie_hellman_t object");
		this->diffie_hellman->destroy(this->diffie_hellman);
	}
	
	this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy object");	
	allocator_free(this);
}

/* 
 * Described in header.
 */
responder_init_t *responder_init_create(protected_ike_sa_t *ike_sa)
{
	private_responder_init_t *this = allocator_alloc_thing(private_responder_init_t);

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private functions */
	this->build_sa_payload = build_sa_payload;
	this->build_ke_payload = build_ke_payload;
	this->build_nonce_payload = build_nonce_payload;
	this->destroy_after_state_change = destroy_after_state_change;
	this->send_notify_reply = send_notify_reply;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	this->sent_nonce = CHUNK_INITIALIZER;
	this->received_nonce = CHUNK_INITIALIZER;
	this->dh_group_number = MODP_UNDEFINED;

	return &(this->public);
}
