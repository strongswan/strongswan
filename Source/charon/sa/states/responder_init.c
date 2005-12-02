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
	 * 
	 * After processing of incoming IKE_SA_INIT-Request the shared key is 
	 * passed to the next state of type ike_sa_init_responded_t.
	 */
	diffie_hellman_t *diffie_hellman;
		
	/**
	 * Diffie Hellman group number.
	 */
	u_int16_t dh_group_number;	
	
	/**
	 * Priority used to get matching dh_group number.
	 */
	u_int16_t dh_group_priority;

	/**
	 * Sent nonce value.
	 * 
	 * This value is passed to the next state of type ike_sa_init_responded_t.
	 */
	chunk_t sent_nonce;
	
	/**
	 * Received nonce value
	 * 
	 * This value is passed to the next state of type ike_sa_init_responded_t.
	 */
	chunk_t received_nonce;
	
	/**
	 * Logger used to log data 
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
	
	/**
	 * Selected proposal from suggested ones.
	 */
	ike_proposal_t selected_proposal;

	/**
	 * Builds the IKE_SA_INIT reply message
	 * 
	 * @param this		calling object
	 * @param message	the message will be written to this location.
	 */
	void (*build_ike_sa_init_reply) (private_responder_init_t *this, message_t **message);

	/**
	 * Builds the SA payload for this state.
	 * 
	 * @param this		calling object
	 * @param payload	The generated SA payload object of type ke_payload_t is 
	 * 					stored at this location.
	 */
	void (*build_sa_payload) (private_responder_init_t *this, payload_t **payload);

	/**
	 * Builds the KE payload for this state.
	 * 
	 * @param this		calling object
	 * @param payload	The generated KE payload object of type ke_payload_t is 
	 * 					stored at this location.
	 */
	void (*build_ke_payload) (private_responder_init_t *this, payload_t **payload);
	
	/**
	 * Builds the NONCE payload for this state.
	 * 
	 * @param this		calling object
	 * @param payload	The generated NONCE payload object of type ke_payload_t is 
	 * 					stored at this location.
	 */
	void (*build_nonce_payload) (private_responder_init_t *this, payload_t **payload);	
	
	/**
	 * Destroy function called internally of this class after state change succeeded.
	 * 
	 * This destroy function does not destroy objects which were passed to the new state.
	 * 
	 * @param this		calling object
	 */
	void (*destroy_after_state_change) (private_responder_init_t *this);
	
	/**
	 * Sends a IKE_SA_INIT reply with a notify payload.
	 * 
	 * @param this		calling object
	 * @param type		type of notify message
	 * @param data		data of notify message
	 */
	void (*send_notify_reply) (private_responder_init_t *this,notify_message_type_t type, chunk_t data);

};

/**
 * Implements state_t.get_state
 */
static status_t process_message(private_responder_init_t *this, message_t *message)
{
	ike_sa_init_responded_t *next_state;
	exchange_type_t	exchange_type;
	host_t *source, *destination;
	init_config_t *init_config;
	randomizer_t *randomizer;
	chunk_t shared_secret;
	iterator_t *payloads;
	message_t *response;
	host_t *other_host;
	host_t *my_host;
	status_t status;

	exchange_type = message->get_exchange_type(message);
	if (exchange_type != IKE_SA_INIT)
	{
		this->logger->log(this->logger, ERROR | MORE, "Message of type %s not supported in state responder_init",mapping_find(exchange_type_m,exchange_type));
		return DELETE_ME;
	}
	if (!message->get_request(message))
	{
		this->logger->log(this->logger, ERROR | MORE, "Only requests of type IKE_SA_INIT supported in state responder_init");
		return DELETE_ME;
	}
	/* this is the first message we process, so get host infos */
	source = message->get_source(message);
	destination = message->get_destination(message);

	status = charon->configuration_manager->get_init_config_for_host(charon->configuration_manager,destination,source,&init_config);
	if (status != SUCCESS)
	{
		/* no configuration matches given host */
		this->logger->log(this->logger, ERROR | MORE, "No INIT configuration found for given remote and local hosts");
		return DELETE_ME;
	}
	
	this->ike_sa->set_init_config(this->ike_sa,init_config);
	
	/* we need to clone them, since we destroy the message later */
	my_host = destination->clone(destination);
	other_host = source->clone(source);
	
	this->ike_sa->set_my_host(this->ike_sa, my_host);
	this->ike_sa->set_other_host(this->ike_sa, other_host);
	
	/* parse incoming message */
	status = message->parse_body(message, NULL, NULL);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR | MORE, "Could not parse body of request message");
		return DELETE_ME;
	}

	/* iterate over incoming payloads. We can be sure, the message contains only accepted payloads! */
	payloads = message->get_payload_iterator(message);
	
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		
		/* get current payload */
		payloads->current(payloads, (void**)&payload);
		
		this->logger->log(this->logger, CONTROL|MORE, "Processing payload of type %s", mapping_find(payload_type_m, payload->get_type(payload)));
		switch (payload->get_type(payload))
		{
			case SECURITY_ASSOCIATION:
			{
				sa_payload_t *sa_payload = (sa_payload_t*)payload;
				ike_proposal_t *ike_proposals;
				size_t proposal_count;
			
				/* get the list of suggested proposals */ 
				status = sa_payload->get_ike_proposals (sa_payload, &ike_proposals,&proposal_count);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR | MORE, "SA payload does not contain IKE proposals");
					payloads->destroy(payloads);
					return DELETE_ME;	
				}
	
				status = init_config->select_proposal(init_config, ike_proposals,proposal_count,&(this->selected_proposal));
				allocator_free(ike_proposals);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR | MORE, "No proposal of suggested proposals selected");
					payloads->destroy(payloads);
					this->send_notify_reply(this,NO_PROPOSAL_CHOSEN,CHUNK_INITIALIZER);			
					return DELETE_ME;
				}
				
				this->dh_group_number = this->selected_proposal.diffie_hellman_group;
				
				status = this->ike_sa->create_transforms_from_proposal(this->ike_sa,&(this->selected_proposal));	
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR | MORE, "Transform objects could not be created from selected proposal");
					payloads->destroy(payloads);
					return DELETE_ME;
				}
				
				this->logger->log(this->logger, CONTROL | MORE, "SA Payload processed");
				/* ok, we have what we need for sa_payload (proposals are stored in this->proposals)*/
				break;
			}
			case KEY_EXCHANGE:
			{
				ke_payload_t *ke_payload = (ke_payload_t*)payload;
				diffie_hellman_group_t group;
				diffie_hellman_t *dh;
				
				group = ke_payload->get_dh_group_number(ke_payload);
				
				if (group == MODP_UNDEFINED)
				{
					this->logger->log(this->logger, ERROR | MORE, "Diffie hellman group set to undefined!");
					payloads->destroy(payloads);
					return DELETE_ME;
				}
				if (this->dh_group_number != group)
				{
					u_int16_t accepted_group;
					chunk_t accepted_group_chunk;
					/* group not same as selected one 
					 * Maybe key exchange payload is before SA payload */
					this->logger->log(this->logger, ERROR | MORE, "Diffie hellman group not as in selected proposal!");
					payloads->destroy(payloads);
					
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
					payloads->destroy(payloads);
					return DELETE_ME;
				}
				this->logger->log(this->logger, CONTROL | MORE, "Set other DH public value");
				
				dh->set_other_public_value(dh, ke_payload->get_key_exchange_data(ke_payload));

				this->diffie_hellman = dh;
				
				this->logger->log(this->logger, CONTROL | MORE, "KE Payload processed.");
				break;
			}
			case NONCE:
			{
				nonce_payload_t *nonce_payload = (nonce_payload_t*)payload;

				allocator_free(this->received_nonce.ptr);
				this->received_nonce = CHUNK_INITIALIZER;

				this->logger->log(this->logger, CONTROL | MORE, "Get nonce value and store it");
				nonce_payload->get_nonce(nonce_payload, &(this->received_nonce));
				
				this->logger->log(this->logger, CONTROL | MORE, "Nonce Payload processed");
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR | MORE, "Payload type not supported!");
				payloads->destroy(payloads);
				return DELETE_ME;
			}
		}
	}
	/* iterator can be destroyed */
	payloads->destroy(payloads);
	
	this->logger->log(this->logger, CONTROL | MORE, "Request successfully handled. Going to create reply.");

	this->logger->log(this->logger, CONTROL | MOST, "Going to create nonce.");	
	
	randomizer = this->ike_sa->get_randomizer(this->ike_sa);
	randomizer->allocate_pseudo_random_bytes(randomizer, NONCE_SIZE, &(this->sent_nonce));

	/* store shared secret  */
	this->logger->log(this->logger, CONTROL | MOST, "Retrieve shared secret and store it.");
	status = this->diffie_hellman->get_shared_secret(this->diffie_hellman, &shared_secret);
	this->logger->log_chunk(this->logger, PRIVATE, "Shared secret", &shared_secret);

	this->ike_sa->compute_secrets(this->ike_sa,shared_secret,this->received_nonce, this->sent_nonce);

	/* not used anymore */
	allocator_free_chunk(&shared_secret);

	this->build_ike_sa_init_reply(this,&response);

	/* message can now be sent (must not be destroyed) */
	status = this->ike_sa->send_response(this->ike_sa, response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not send response message");
		response->destroy(response);
		return DELETE_ME;
	}



	/* state can now be changed */
	this->logger->log(this->logger, CONTROL|MOST, "Create next state object");

	next_state = ike_sa_init_responded_create(this->ike_sa, this->received_nonce);
	
	/* state can now be changed */
	this->ike_sa->set_new_state(this->ike_sa, (state_t *) next_state);
	/* state has NOW changed :-) */
	this->logger->log(this->logger, CONTROL|MORE, "Changed state of IKE_SA from %s to %s",mapping_find(ike_sa_state_m,RESPONDER_INIT),mapping_find(ike_sa_state_m,IKE_SA_INIT_RESPONDED) );

	this->logger->log(this->logger, CONTROL|MOST, "Destroy old sate object");
	this->destroy_after_state_change(this);	
	
	return SUCCESS;
}


/**
 * implements private_responder_init_t.build_ike_sa_init_reply
 */
static void build_ike_sa_init_reply (private_responder_init_t *this, message_t **message)
{
	message_t *response;
	payload_t *payload;
	
	this->logger->log(this->logger, CONTROL|MOST, "Going to build message");
	/* set up the reply */
	this->ike_sa->build_message(this->ike_sa, IKE_SA_INIT, FALSE, &response);
	
	/* build SA payload */		
	this->build_sa_payload(this, &payload);
	this->logger->log(this->logger, CONTROL|MOST, "add SA payload to message");
	response->add_payload(response, payload);
	
	/* build KE payload */
	this->build_ke_payload(this,&payload);
	this->logger->log(this->logger, CONTROL|MOST, "add KE payload to message");
	response->add_payload(response, payload);
	
	/* build Nonce payload */
	this->build_nonce_payload(this, &payload);
	this->logger->log(this->logger, CONTROL|MOST, "add nonce payload to message");
	response->add_payload(response, payload);
	
	*message = response;
}

/**
 * implements private_initiator_init_t.build_sa_payload
 */
static void build_sa_payload(private_responder_init_t *this, payload_t **payload)
{
	sa_payload_t* sa_payload;
	
	this->logger->log(this->logger, CONTROL|MORE, "building sa payload");
	sa_payload = sa_payload_create_from_ike_proposals(&(this->selected_proposal),1);	
	
	*payload = (payload_t *) sa_payload;
}

/**
 * implements private_initiator_init_t.build_ke_payload
 */
static void build_ke_payload(private_responder_init_t *this, payload_t **payload)
{
	ke_payload_t *ke_payload;
	chunk_t key_data;

	this->logger->log(this->logger, CONTROL|MORE, "building ke payload");
	this->diffie_hellman->get_my_public_value(this->diffie_hellman,&key_data);

	ke_payload = ke_payload_create();
	ke_payload->set_key_exchange_data(ke_payload,key_data);
	ke_payload->set_dh_group_number(ke_payload, this->dh_group_number);
	allocator_free_chunk(&key_data);

	*payload = (payload_t *) ke_payload;
}

/**
 * implements private_initiator_init_t.build_nonce_payload
 */
static void build_nonce_payload(private_responder_init_t *this, payload_t **payload)
{
	nonce_payload_t *nonce_payload;
	
	this->logger->log(this->logger, CONTROL|MORE, "building nonce payload");
	nonce_payload = nonce_payload_create();
	nonce_payload->set_nonce(nonce_payload, this->sent_nonce);
	
	*payload = (payload_t *) nonce_payload;
}


/**
 * Implements state_t.get_state
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
	
	this->logger->log(this->logger, CONTROL|MOST, "Going to build message with notify payload");
	/* set up the reply */
	this->ike_sa->build_message(this->ike_sa, IKE_SA_INIT, FALSE, &response);
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
 * Implements state_t.get_state
 */
static void destroy(private_responder_init_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy responder init state object");
	
	this->logger->log(this->logger, CONTROL | MOST, "Destroy sent nonce");
	allocator_free_chunk(&(this->sent_nonce));
	this->logger->log(this->logger, CONTROL | MOST, "Destroy received nonce");
	allocator_free_chunk(&(this->received_nonce));

	if (this->diffie_hellman != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy diffie_hellman_t hellman object");
		this->diffie_hellman->destroy(this->diffie_hellman);
	}
	this->logger->log(this->logger, CONTROL | MOST, "Destroy object");
	allocator_free(this);
}

/**
 * Implements private_responder_init_t.destroy_after_state_change
 */
static void destroy_after_state_change (private_responder_init_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy responder_init_t state object");
	
	/* destroy diffie hellman object */
	if (this->diffie_hellman != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy diffie_hellman_t object");
		this->diffie_hellman->destroy(this->diffie_hellman);
	}
	
	this->logger->log(this->logger, CONTROL | MOST, "Destroy sent nonce");
	allocator_free_chunk(&(this->sent_nonce));
	this->logger->log(this->logger, CONTROL | MOST, "Destroy object");	
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
	this->build_ike_sa_init_reply = build_ike_sa_init_reply;
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
