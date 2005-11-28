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

#include <globals.h>
#include <sa/states/state.h>
#include <sa/states/ike_sa_init_responded.h>
#include <utils/allocator.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/nonce_payload.h>
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
	 * Proposals used to initiate connection
	 */
	linked_list_t *proposals;
	
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
};

/**
 * Implements state_t.get_state
 */
static status_t process_message(private_responder_init_t *this, message_t *message)
{
	iterator_t *payloads;
	host_t *source, *destination;
	status_t status;
	message_t *response;
	payload_t *payload;
	packet_t *packet;
	chunk_t shared_secret;
	exchange_type_t	exchange_type;
	ike_sa_init_responded_t *next_state;
	host_t *my_host;
	host_t *other_host;
	randomizer_t *randomizer;

	exchange_type = message->get_exchange_type(message);
	if (exchange_type != IKE_SA_INIT)
	{
		this->logger->log(this->logger, ERROR | MORE, "Message of type %s not supported in state responder_init",mapping_find(exchange_type_m,exchange_type));
		return FAILED;
	}
	
	if (!message->get_request(message))
	{
		this->logger->log(this->logger, ERROR | MORE, "Only requests of type IKE_SA_INIT supported in state responder_init");
		return FAILED;
	}
	
	/* this is the first message we process, so copy host infos */
	message->get_source(message, &source);
	message->get_destination(message, &destination);
	
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
		return status;
	}

	/* iterate over incoming payloads. We can be sure, the message contains only accepted payloads! */
	message->get_payload_iterator(message, &payloads);
	
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
				iterator_t *suggested_proposals, *accepted_proposals;
				proposal_substructure_t *accepted_proposal;
				
				this->proposals->create_iterator(this->proposals, &accepted_proposals, FALSE);
				
				/* get the list of suggested proposals */ 
				sa_payload->create_proposal_substructure_iterator(sa_payload, &suggested_proposals, TRUE);
				
				/* now let the configuration-manager select a subset of the proposals */
				status = global_configuration_manager->select_proposals_for_host(global_configuration_manager,
									this->ike_sa->get_other_host(this->ike_sa), suggested_proposals, accepted_proposals);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, CONTROL | MORE, "No proposal of suggested proposals selected");
					suggested_proposals->destroy(suggested_proposals);
					accepted_proposals->destroy(accepted_proposals);
					payloads->destroy(payloads);
					return status;
				}
				
				/* iterators are not needed anymore */			
				suggested_proposals->destroy(suggested_proposals);
				
				/* let the ike_sa create their own transforms from proposal informations */
				accepted_proposals->reset(accepted_proposals);
				/* TODO check for true*/
				accepted_proposals->has_next(accepted_proposals);
				status = accepted_proposals->current(accepted_proposals,(void **)&accepted_proposal);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR | MORE, "Accepted proposals not supported?!");
					accepted_proposals->destroy(accepted_proposals);
					payloads->destroy(payloads);
					return status;
				}
				
				status = this->ike_sa->create_transforms_from_proposal(this->ike_sa,accepted_proposal);	
				accepted_proposals->destroy(accepted_proposals);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR | MORE, "Transform objects could not be created from selected proposal");
					payloads->destroy(payloads);
					return status;
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
				bool allowed_group;
				
				group = ke_payload->get_dh_group_number(ke_payload);
				
				status = global_configuration_manager->is_dh_group_allowed_for_host(global_configuration_manager,
								this->ike_sa->get_other_host(this->ike_sa), group, &allowed_group);

				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR | MORE, "Could not get informations about DH group");
					payloads->destroy(payloads);
					return status;
				}
				if (!allowed_group)
				{
					/** @todo Send info reply */	
				}
				
				/* create diffie hellman object to handle DH exchange */
				dh = diffie_hellman_create(group);
				if (dh == NULL)
				{
					this->logger->log(this->logger, ERROR, "Could not generate DH object");
					payloads->destroy(payloads);
					return NOT_SUPPORTED;
				}

				this->logger->log(this->logger, CONTROL | MORE, "Set other DH public value");
				
				dh->set_other_public_value(dh, ke_payload->get_key_exchange_data(ke_payload));

				this->diffie_hellman = dh;
				
				this->logger->log(this->logger, CONTROL | MORE, "KE Payload processed");
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
				return NOT_SUPPORTED;
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
	this->logger->log(this->logger, CONTROL | MOST, "Retrieve shared secret and store it");
	status = this->diffie_hellman->get_shared_secret(this->diffie_hellman, &shared_secret);
	this->logger->log_chunk(this->logger, PRIVATE, "Shared secret", &shared_secret);

	this->ike_sa->compute_secrets(this->ike_sa,shared_secret,this->received_nonce, this->sent_nonce);

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
	
	/* generate packet */	
	this->logger->log(this->logger, CONTROL|MOST, "generate packet from message");
	status = response->generate(response, NULL, NULL, &packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "could not generate packet from message");
		return status;
	}
	
	this->logger->log(this->logger, CONTROL|MOST, "Add packet to global send queue");
	 global_send_queue->add(global_send_queue, packet);

	/* state can now be changed */
	this->logger->log(this->logger, CONTROL|MOST, "Create next state object");

	next_state = ike_sa_init_responded_create(this->ike_sa, shared_secret, this->received_nonce, this->sent_nonce);
	
	/* last message can now be set */
	status = this->ike_sa->set_last_responded_message(this->ike_sa, response);

	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not set last responded message");
		response->destroy(response);
		(next_state->state_interface).destroy(&(next_state->state_interface));
		return status;
	}

	/* state can now be changed */
	this->ike_sa->set_new_state(this->ike_sa, (state_t *) next_state);
	/* state has NOW changed :-) */
	this->logger->log(this->logger, CONTROL|MORE, "Changed state of IKE_SA from %s to %s",mapping_find(ike_sa_state_m,RESPONDER_INIT),mapping_find(ike_sa_state_m,IKE_SA_INIT_RESPONDED) );

	this->logger->log(this->logger, CONTROL|MOST, "Destroy old sate object");
	this->destroy_after_state_change(this);	
	
	return SUCCESS;
}

/**
 * implements private_initiator_init_t.build_sa_payload
 */
static void build_sa_payload(private_responder_init_t *this, payload_t **payload)
{
	sa_payload_t* sa_payload;
	iterator_t *proposal_iterator;
	
	/* SA payload takes proposals from this->ike_sa_init_data.proposals and writes them to the created sa_payload */
	
	this->logger->log(this->logger, CONTROL|MORE, "building sa payload");
	
	this->proposals->create_iterator(this->proposals, &proposal_iterator, FALSE);
	
	sa_payload = sa_payload_create();
	
	while (proposal_iterator->has_next(proposal_iterator))
	{
		proposal_substructure_t *current_proposal;
		proposal_substructure_t *current_proposal_clone;
		
		proposal_iterator->current(proposal_iterator,(void **) &current_proposal);
		current_proposal->clone(current_proposal,&current_proposal_clone);
		sa_payload->add_proposal_substructure(sa_payload,current_proposal_clone);
	}
	
	proposal_iterator->destroy(proposal_iterator);	
	
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
	ke_payload->set_dh_group_number(ke_payload, MODP_1024_BIT);

	allocator_free_chunk(&key_data);
	*payload = (payload_t *) ke_payload;
}

/**
 * implements private_initiator_init_t.build_nonce_payload
 */
static void build_nonce_payload(private_responder_init_t *this, payload_t **payload)
{
	nonce_payload_t *nonce_payload;
	status_t status;
	
	this->logger->log(this->logger, CONTROL|MORE, "building nonce payload");
	
	nonce_payload = nonce_payload_create();
	
	status = nonce_payload->set_nonce(nonce_payload, this->sent_nonce);
	
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
 * Implements state_t.get_state
 */
static void destroy(private_responder_init_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy responder init state object");
	
	/* destroy stored proposal */
	this->logger->log(this->logger, CONTROL | MOST, "Destroy stored proposals");
	while (this->proposals->get_count(this->proposals) > 0)
	{
		proposal_substructure_t *current_proposal;
		this->proposals->remove_first(this->proposals,(void **)&current_proposal);
		current_proposal->destroy(current_proposal);
	}
	this->proposals->destroy(this->proposals);
	
	allocator_free(this->sent_nonce.ptr);
	allocator_free(this->received_nonce.ptr);

	if (this->diffie_hellman != NULL)
	{
		this->diffie_hellman->destroy(this->diffie_hellman);
	}
	allocator_free(this);
}

/**
 * Implements private_responder_init_t.destroy_after_state_change
 */
static void destroy_after_state_change (private_responder_init_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy responder_init_t state object");
	
	/* destroy stored proposal */
	this->logger->log(this->logger, CONTROL | MOST, "Destroy stored proposals");
	while (this->proposals->get_count(this->proposals) > 0)
	{
		proposal_substructure_t *current_proposal;
		this->proposals->remove_first(this->proposals,(void **)&current_proposal);
		current_proposal->destroy(current_proposal);
	}
	this->proposals->destroy(this->proposals);
	
	/* destroy diffie hellman object */
	if (this->diffie_hellman != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy diffie_hellman_t object");
		this->diffie_hellman->destroy(this->diffie_hellman);
	}
	
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
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	this->sent_nonce = CHUNK_INITIALIZER;
	this->received_nonce = CHUNK_INITIALIZER;
	this->proposals = linked_list_create();

	return &(this->public);
}
