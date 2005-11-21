/**
 * @file initiator_init.c
 * 
 * @brief Start state of a IKE_SA as initiator
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
 
#include "initiator_init.h"


#include "state.h"
#include "ike_sa_init_requested.h"
#include "../globals.h"
#include "../utils/allocator.h"
#include "../transforms/diffie_hellman.h"
#include "../payloads/sa_payload.h"
#include "../payloads/ke_payload.h"
#include "../payloads/nonce_payload.h"


/**
 * Private data of a initiator_init_t object.
 *
 */
typedef struct private_initiator_init_s private_initiator_init_t;
struct private_initiator_init_s {
	/**
	 * methods of the state_t interface
	 */
	initiator_init_t public;
	
	/**
	 * Assigned IKE_SA
	 */
	protected_ike_sa_t *ike_sa;
	
	/**
	 * Diffie hellman object
	 */
	diffie_hellman_t *diffie_hellman;
	
	/**
	 * DH group number
	 */
	u_int16_t dh_group_number;
	
	/**
	 * DH group priority
	 */
	u_int16_t dh_group_priority;
	
	/**
	 * Sent nonce
	 */
	chunk_t sent_nonce;
	
	/**
	 * Proposals used to initiate connection
	 */
	linked_list_t *proposals;

	/**
	 * Logger used to log data 
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
	
	status_t (*build_sa_payload) (private_initiator_init_t *this, payload_t **payload);
	status_t (*build_ke_payload) (private_initiator_init_t *this, payload_t **payload);
	status_t (*build_nonce_payload) (private_initiator_init_t *this, payload_t **payload);	
	
	status_t (*destroy_after_state_change) (private_initiator_init_t *this);
};

static status_t initiate_connection (private_initiator_init_t *this, char *name, state_t **new_state)
{
	message_t *message;
	payload_t *payload;
	packet_t *packet;
	status_t status;
	linked_list_iterator_t *proposal_iterator;
	ike_sa_init_requested_t *next_state;

	
	this->logger->log(this->logger, CONTROL, "Initializing connection %s",name);
	
	status = global_configuration_manager->get_local_host(global_configuration_manager, name, &(this->ike_sa->me.host));
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR | MORE, "Could not retrieve local host configuration information for %s",name);
		return INVALID_ARG;
	}
	
	status = global_configuration_manager->get_remote_host(global_configuration_manager, name, &(this->ike_sa->other.host));
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR | MORE, "Could not retrieve remote host configuration information for %s",name);
		return INVALID_ARG;
	}
	
	status = global_configuration_manager->get_dh_group_number(global_configuration_manager, name, &(this->dh_group_number), this->dh_group_priority);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR | MORE, "Could not retrieve DH group number for %s",name);
		return INVALID_ARG;
	}

	status = this->proposals->create_iterator(this->proposals, &proposal_iterator, FALSE);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: Could not create iterator on list for proposals");
		return status;	
	}
	
	status = global_configuration_manager->get_proposals_for_host(global_configuration_manager, this->ike_sa->other.host, proposal_iterator);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR | MORE, "Could not retrieve Proposals for %s",name);
		return status;
	}
	/* not needed anymore */
	proposal_iterator->destroy(proposal_iterator);
	
	this	->logger->log(this->logger, CONTROL|MOST, "create diffie hellman object");
	this->diffie_hellman = diffie_hellman_create(this->dh_group_number);
	
	if (this->diffie_hellman == NULL)
	{
		this->logger->log(this->logger, ERROR, "Object of type diffie_hellman_t could not be created!");
		return FAILED;			
	}
	
	
	if (this->ike_sa->randomizer->allocate_pseudo_random_bytes(this->ike_sa->randomizer, NONCE_SIZE, &(this->sent_nonce)) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not create nonce!");
		return OUT_OF_RES;
	}
		
	
	/* going to build message */
	status = this->ike_sa->build_message(this->ike_sa, IKE_SA_INIT, TRUE, &message);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not build message");
		return status;
	}

	/* build SA payload */		
	status = this->build_sa_payload(this, &payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not build SA payload");
		message->destroy(message);
		return status;
	}
	
	this	->logger->log(this->logger, CONTROL|MOST, "add SA payload to message");
	status = message->add_payload(message, payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not add SA payload to message");
		message->destroy(message);
		return status;
	}

	
	/* build KE payload */
	status = this->build_ke_payload(this, &payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not build KE payload");
		message->destroy(message);
		return status;
	}

	this	->logger->log(this->logger, CONTROL|MOST, "add KE payload to message");
	status = message->add_payload(message, payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not add KE payload to message");
		message->destroy(message);
		return status;
	}
	
	/* build Nonce payload */
	status = this->build_nonce_payload(this, &payload);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not build NONCE payload");
		message->destroy(message);
		return status;
	}

	this	->logger->log(this->logger, CONTROL|MOST, "add nonce payload to message");
	status = message->add_payload(message, payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not add nonce payload to message");
		message->destroy(message);
		return status;
	}

	/* generate packet */	
	this	->logger->log(this->logger, CONTROL|MOST, "generate packet from message");
	status = message->generate(message, &packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: could not generate packet from message");
		message->destroy(message);
		return status;
	}
	
	this	->logger->log(this->logger, CONTROL|MOST, "Add packet to global send queue");
	status = global_send_queue->add(global_send_queue, packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not add packet to send queue");
		message->destroy(message);
		return status;
	}

	if (	this->ike_sa->last_requested_message != NULL)
	{
		/* destroy message */
		this	->logger->log(this->logger, CONTROL|MOST, "Destroy stored last requested message");
		this->ike_sa->last_requested_message->destroy(this->ike_sa->last_requested_message);
	}

	this->ike_sa->last_requested_message	 = message;

	/* message counter can now be increased */
	this->ike_sa->message_id_out++;
	
	
	/* state can now be changed */
	next_state = ike_sa_init_requested_create(this->ike_sa,this->diffie_hellman,this->sent_nonce);

	if (next_state == NULL)
	{
		this	->logger->log(this->logger, ERROR, "Fatal error: could not create next state object of type ike_sa_init_requested_t");
		return FAILED;
	}

	/* state has NOW changed :-) */
	this	->logger->log(this->logger, CONTROL|MORE, "Change state of IKE_SA from %s to %s",mapping_find(ike_sa_state_m,INITIATOR_INIT),mapping_find(ike_sa_state_m,IKE_SA_INIT_REQUESTED) );

	this->destroy_after_state_change(this);

	*new_state = (state_t *) next_state;

	return SUCCESS;
}

/**
 * implements private_initiator_init_t.build_sa_payload
 */
static status_t build_sa_payload(private_initiator_init_t *this, payload_t **payload)
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
static status_t build_ke_payload(private_initiator_init_t *this, payload_t **payload)
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
static status_t build_nonce_payload(private_initiator_init_t *this, payload_t **payload)
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
static status_t process_message(private_initiator_init_t *this, message_t *message, state_t **new_state)
{
	*new_state = (state_t *) this;
	return FAILED;
}

/**
 * Implements state_t.get_state
 */
static ike_sa_state_t get_state(private_initiator_init_t *this)
{
	return INITIATOR_INIT;
}

/**
 * Implements state_t.get_state
 */
static status_t destroy(private_initiator_init_t *this)
{
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

/**
 * Implements private_initiator_init_t.destroy_after_state_change
 */
static status_t destroy_after_state_change (private_initiator_init_t *this)
{
	/* destroy stored proposal */
	this->logger->log(this->logger, CONTROL | MOST, "Destroy stored proposals");
	while (this->proposals->get_count(this->proposals) > 0)
	{
		proposal_substructure_t *current_proposal;
		this->proposals->remove_first(this->proposals,(void **)&current_proposal);
		current_proposal->destroy(current_proposal);
	}
	this->proposals->destroy(this->proposals);
	allocator_free(this);
	return SUCCESS;
}

/* 
 * Described in header.
 */
initiator_init_t *initiator_init_create(protected_ike_sa_t *ike_sa)
{
	private_initiator_init_t *this = allocator_alloc_thing(private_initiator_init_t);
	
	if (this == NULL)
	{
		return NULL;
	}

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *,state_t **)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (status_t (*) (state_t *)) destroy;
	
	/* public functions */
	this->public.initiate_connection = (status_t (*)(initiator_init_t *, char *, state_t **)) initiate_connection;
	
	/* private functions */
	this->build_sa_payload = build_sa_payload;
	this->build_ke_payload = build_ke_payload;
	this->build_nonce_payload = build_nonce_payload;
	this->destroy_after_state_change = destroy_after_state_change;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = this->ike_sa->logger;
	this->dh_group_priority = 1;
	this->proposals = linked_list_create();
	this->sent_nonce.ptr = NULL;
	this->sent_nonce.len = 0;
	if (this->proposals == NULL)
	{
		allocator_free(this);
		return NULL;
	}
	
	return &(this->public);
}
