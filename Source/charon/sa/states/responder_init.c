/**
 * @file responder_init.c
 * 
 * @brief Start state of a IKE_SA as responder
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

/**
 * Private data of a responder_init_t object.
 *
 */
typedef struct private_responder_init_s private_responder_init_t;
struct private_responder_init_s {
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
	 * @return			
	 * 					- SUCCESS
	 * 					- OUT_OF_RES
	 */
	status_t (*build_sa_payload) (private_responder_init_t *this, payload_t **payload);

	/**
	 * Builds the KE payload for this state.
	 * 
	 * @param this		calling object
	 * @param payload	The generated KE payload object of type ke_payload_t is 
	 * 					stored at this location.
	 * @return			
	 * 					- SUCCESS
	 * 					- OUT_OF_RES
	 */
	status_t (*build_ke_payload) (private_responder_init_t *this, payload_t **payload);
	/**
	 * Builds the NONCE payload for this state.
	 * 
	 * @param this		calling object
	 * @param payload	The generated NONCE payload object of type ke_payload_t is 
	 * 					stored at this location.
	 * @return			
	 * 					- SUCCESS
	 * 					- OUT_OF_RES
	 */
	status_t (*build_nonce_payload) (private_responder_init_t *this, payload_t **payload);	
	
	/**
	 * Destroy function called internally of this class after state change succeeded.
	 * 
	 * This destroy function does not destroy objects which were passed to the new state.
	 * 
	 * @param this		calling object
	 * @return			SUCCESS in any case
	 */
	status_t (*destroy_after_state_change) (private_responder_init_t *this);
};

/**
 * Implements state_t.get_state
 */
static status_t process_message(private_responder_init_t *this, message_t *message, state_t **new_state)
{
	linked_list_iterator_t *payloads;
	host_t *source, *destination;
	status_t status;
	message_t *response;
	payload_t *payload;
	packet_t *packet;
	chunk_t shared_secret;
	exchange_type_t	exchange_type;
	ike_sa_init_responded_t *next_state;

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
	destination->clone(destination, &(this->ike_sa->me.host));
	source->clone(source, &(this->ike_sa->other.host));
	
	/* parse incoming message */
	status = message->parse_body(message);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR | MORE, "Could not parse body of request message");
		return status;	
	}

	/* iterate over incoming payloads. We can be sure, the message contains only accepted payloads! */
	status = message->get_payload_iterator(message, &payloads);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: Could not get payload interator");
		return status;
	}
	
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
				linked_list_iterator_t *suggested_proposals, *accepted_proposals;
				encryption_algorithm_t		encryption_algorithm = ENCR_UNDEFINED;
				pseudo_random_function_t		pseudo_random_function = PRF_UNDEFINED;
				integrity_algorithm_t		integrity_algorithm = AUTH_UNDEFINED;

				status = this->proposals->create_iterator(this->proposals, &accepted_proposals, FALSE);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR, "Fatal error: Could not create iterator on list for proposals");
					payloads->destroy(payloads);
					return status;	
				}
				
				/* get the list of suggested proposals */ 
				status = sa_payload->create_proposal_substructure_iterator(sa_payload, &suggested_proposals, TRUE);
				if (status != SUCCESS)
				{	
					this->logger->log(this->logger, ERROR, "Fatal error: Could not create iterator on suggested proposals");
					accepted_proposals->destroy(accepted_proposals);
					payloads->destroy(payloads);
					return status;
				}
				
				/* now let the configuration-manager select a subset of the proposals */
				status = global_configuration_manager->select_proposals_for_host(global_configuration_manager,
									this->ike_sa->other.host, suggested_proposals, accepted_proposals);
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
					
				
				/* now let the configuration-manager return the transforms for the given proposal*/
				this->logger->log(this->logger, CONTROL | MOST, "Get transforms for accepted proposal");
				status = global_configuration_manager->get_transforms_for_host_and_proposals(global_configuration_manager,
									this->ike_sa->other.host, accepted_proposals, &encryption_algorithm,&pseudo_random_function,&integrity_algorithm);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR | MORE, "Accepted proposals not supported?!");
					accepted_proposals->destroy(accepted_proposals);
					payloads->destroy(payloads);
					return status;
				}
				accepted_proposals->destroy(accepted_proposals);
				
				this->ike_sa->prf = prf_create(pseudo_random_function);
				if (this->ike_sa->prf == NULL)
				{
					this->logger->log(this->logger, ERROR | MORE, "PRF type not supported");
					payloads->destroy(payloads);
					return FAILED;
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
								this->ike_sa->other.host, group, &allowed_group);

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
					return OUT_OF_RES;
				}

				this->logger->log(this->logger, CONTROL | MORE, "Set other DH public value");
				
				status = dh->set_other_public_value(dh, ke_payload->get_key_exchange_data(ke_payload));
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR, "Could not set other DH public value");
					dh->destroy(dh);
					payloads->destroy(payloads);
					return OUT_OF_RES;
				}

				this->diffie_hellman = dh;
				
				this->logger->log(this->logger, CONTROL | MORE, "KE Payload processed");
				break;
			}
			case NONCE:
			{
				nonce_payload_t *nonce_payload = (nonce_payload_t*)payload;

				if (this->received_nonce.ptr != NULL)
				{
					this->logger->log(this->logger, CONTROL | MOST, "Destroy stored received nonce");
					allocator_free(this->received_nonce.ptr);
					this->received_nonce.ptr = NULL;
					this->received_nonce.len = 0;
				}

				this->logger->log(this->logger, CONTROL | MORE, "Get nonce value and store it");
				status = nonce_payload->get_nonce(nonce_payload, &(this->received_nonce));
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR, "Fatal error: Could not get nonce");
					payloads->destroy(payloads);
					return OUT_OF_RES;
				}
				
				this->logger->log(this->logger, CONTROL | MORE, "Nonce Payload processed");
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR | MORE, "Payload type not supported!");
				payloads->destroy(payloads);
				return OUT_OF_RES;
			}
				
		}
			
	}
	/* iterator can be destroyed */
	payloads->destroy(payloads);
	
	this->logger->log(this->logger, CONTROL | MORE, "Request successfully handled. Going to create reply.");

	this->logger->log(this->logger, CONTROL | MOST, "Going to create nonce.");		
	if (this->ike_sa->randomizer->allocate_pseudo_random_bytes(this->ike_sa->randomizer, NONCE_SIZE, &(this->sent_nonce)) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not create nonce!");
		return OUT_OF_RES;
	}
	
	/* store shared secret  */
	this->logger->log(this->logger, CONTROL | MOST, "Retrieve shared secret and store it");
	status = this->diffie_hellman->get_shared_secret(this->diffie_hellman, &shared_secret);
	this->logger->log_chunk(this->logger, PRIVATE, "Shared secret", &shared_secret);

	status = this->ike_sa->compute_secrets(this->ike_sa,shared_secret,this->received_nonce, this->sent_nonce);
	if (status != SUCCESS)
	{
		/* secrets could not be computed */
		this->logger->log(this->logger, ERROR | MORE, "Secrets could not be computed!");
		return status;
	}
	
		

	/* set up the reply */
	status = this->ike_sa->build_message(this->ike_sa, IKE_SA_INIT, FALSE, &response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not create empty message");
		return status;	
	}
	
	/* build SA payload */		
	status = this->build_sa_payload(this, &payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not build SA payload");
		return status;
	}
	
	this	->logger->log(this->logger, CONTROL|MOST, "add SA payload to message");
	status = response->add_payload(response, payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not add SA payload to message");
		return status;
	}
	
	/* build KE payload */
	status = this->build_ke_payload(this,&payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not build KE payload");
		return status;
	}

	this	->logger->log(this->logger, CONTROL|MOST, "add KE payload to message");
	status = response->add_payload(response, payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not add KE payload to message");
		return status;
	}
	
	/* build Nonce payload */
	status = this->build_nonce_payload(this, &payload);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not build NONCE payload");
		return status;
	}

	this	->logger->log(this->logger, CONTROL|MOST, "add nonce payload to message");
	status = response->add_payload(response, payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not add nonce payload to message");
		return status;
	}
	
	/* generate packet */	
	this	->logger->log(this->logger, CONTROL|MOST, "generate packet from message");
	status = response->generate(response, &packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: could not generate packet from message");
		return status;
	}
	
	this	->logger->log(this->logger, CONTROL|MOST, "Add packet to global send queue");
	status = global_send_queue->add(global_send_queue, packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not add packet to send queue");
		return status;
	}

	/* state can now be changed */
	this	->logger->log(this->logger, CONTROL|MOST, "Create next state object");

	next_state = ike_sa_init_responded_create(this->ike_sa, shared_secret, this->received_nonce, this->sent_nonce);

	if (next_state == NULL)
	{
		this	->logger->log(this->logger, ERROR, "Fatal error: could not create next state object of type ike_sa_init_responded_t");
		allocator_free_chunk(shared_secret);
		return FAILED;
	}
	
	if (	this->ike_sa->last_responded_message != NULL)
	{
		/* destroy message */
		this	->logger->log(this->logger, CONTROL|MOST, "Destroy stored last responded message");
		this->ike_sa->last_responded_message->destroy(this->ike_sa->last_responded_message);
	}
	this->ike_sa->last_responded_message	 = response;

	/* message counter can now be increased */
	this	->logger->log(this->logger, CONTROL|MOST, "Increate message counter for incoming messages");
	this->ike_sa->message_id_in++;

	*new_state = (state_t *) next_state;
	/* state has NOW changed :-) */
	this	->logger->log(this->logger, CONTROL|MORE, "Changed state of IKE_SA from %s to %s",mapping_find(ike_sa_state_m,RESPONDER_INIT),mapping_find(ike_sa_state_m,IKE_SA_INIT_RESPONDED) );

	this	->logger->log(this->logger, CONTROL|MOST, "Destroy old sate object");
	this->destroy_after_state_change(this);	
	
	return SUCCESS;
}

/**
 * implements private_initiator_init_t.build_sa_payload
 */
static status_t build_sa_payload(private_responder_init_t *this, payload_t **payload)
{
	sa_payload_t* sa_payload;
	linked_list_iterator_t *proposal_iterator;
	status_t status;
	
	
	/* SA payload takes proposals from this->ike_sa_init_data.proposals and writes them to the created sa_payload */

	this->logger->log(this->logger, CONTROL|MORE, "building sa payload");
	
	status = this->proposals->create_iterator(this->proposals, &proposal_iterator, FALSE);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: Could not create iterator on list for proposals");
		return status;	
	}
	
	sa_payload = sa_payload_create();
	if (sa_payload == NULL)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: Could not create SA payload object");
		return OUT_OF_RES;
	}
	
	while (proposal_iterator->has_next(proposal_iterator))
	{
		proposal_substructure_t *current_proposal;
		proposal_substructure_t *current_proposal_clone;
		status = proposal_iterator->current(proposal_iterator,(void **) &current_proposal);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, ERROR, "Could not get current proposal needed to copy");
			proposal_iterator->destroy(proposal_iterator);
			sa_payload->destroy(sa_payload);
			return status;	
		}
		status = current_proposal->clone(current_proposal,&current_proposal_clone);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, ERROR, "Could not clone current proposal");
			proposal_iterator->destroy(proposal_iterator);
			sa_payload->destroy(sa_payload);
			return status;	
		}
		
		status = sa_payload->add_proposal_substructure(sa_payload,current_proposal_clone);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, ERROR, "Could not add cloned proposal to SA payload");
			proposal_iterator->destroy(proposal_iterator);
			sa_payload->destroy(sa_payload);
			return status;	
		}

	}

	proposal_iterator->destroy(proposal_iterator);	
	
	this->logger->log(this->logger, CONTROL|MORE, "sa payload builded");
	
	*payload = (payload_t *) sa_payload;
	
	return SUCCESS;
}

/**
 * implements private_initiator_init_t.build_ke_payload
 */
static status_t build_ke_payload(private_responder_init_t *this, payload_t **payload)
{
	ke_payload_t *ke_payload;
	chunk_t key_data;
	status_t status;

	this->logger->log(this->logger, CONTROL|MORE, "building ke payload");
	

	this	->logger->log(this->logger, CONTROL|MORE, "get public dh value to send in ke payload");
	status = this->diffie_hellman->get_my_public_value(this->diffie_hellman,&key_data);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not get my DH public value");
		return status;
	}

	ke_payload = ke_payload_create();
	if (ke_payload == NULL)
	{
		this->logger->log(this->logger, ERROR, "Could not create KE payload");
		allocator_free_chunk(key_data);
		return OUT_OF_RES;	
	}
	ke_payload->set_dh_group_number(ke_payload, MODP_1024_BIT);
	if (ke_payload->set_key_exchange_data(ke_payload, key_data) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not set key exchange data of KE payload");
		ke_payload->destroy(ke_payload);
		allocator_free_chunk(key_data);
		return OUT_OF_RES;
	}
	allocator_free_chunk(key_data);

	*payload = (payload_t *) ke_payload;
	return SUCCESS;			
}

/**
 * implements private_initiator_init_t.build_nonce_payload
 */
static status_t build_nonce_payload(private_responder_init_t *this, payload_t **payload)
{
	nonce_payload_t *nonce_payload;
	status_t status;
	
	this->logger->log(this->logger, CONTROL|MORE, "building nonce payload");

	nonce_payload = nonce_payload_create();
	if (nonce_payload == NULL)
	{	
		this->logger->log(this->logger, ERROR, "Fatal error: could not create nonce payload object");
		return OUT_OF_RES;	
	}

	status = nonce_payload->set_nonce(nonce_payload, this->sent_nonce);
	
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: could not set nonce data of payload");
		nonce_payload->destroy(nonce_payload);
		return status;
	}
		
	*payload = (payload_t *) nonce_payload;
	
	return SUCCESS;
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
static status_t destroy(private_responder_init_t *this)
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
	
	if (this->sent_nonce.ptr != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy sent nonce");
		allocator_free(this->sent_nonce.ptr);
	}

	if (this->received_nonce.ptr != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy received nonce");
		allocator_free(this->received_nonce.ptr);
	}
	
	/* destroy diffie hellman object */
	if (this->diffie_hellman != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy diffie_hellman_t object");
		this->diffie_hellman->destroy(this->diffie_hellman);
	}
	
	allocator_free(this);
		
	return SUCCESS;
	
}

/**
 * Implements private_responder_init_t.destroy_after_state_change
 */
static status_t destroy_after_state_change (private_responder_init_t *this)
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
	return SUCCESS;
}

/* 
 * Described in header.
 */
responder_init_t *responder_init_create(protected_ike_sa_t *ike_sa)
{
	private_responder_init_t *this = allocator_alloc_thing(private_responder_init_t);
	
	if (this == NULL)
	{
		return NULL;
	}

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *,state_t **)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (status_t (*) (state_t *)) destroy;
	
	/* private functions */
	this->build_sa_payload = build_sa_payload;
	this->build_ke_payload = build_ke_payload;
	this->build_nonce_payload = build_nonce_payload;
	this->destroy_after_state_change = destroy_after_state_change;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = this->ike_sa->logger;
	this->sent_nonce.ptr = NULL;
	this->sent_nonce.len = 0;
	this->received_nonce.ptr = NULL;
	this->received_nonce.len = 0;
	this->proposals = linked_list_create();
	if (this->proposals == NULL)
	{
		allocator_free(this);
		return NULL;
	}
	
	return &(this->public);
}
