/**
 * @file initiator_init.c
 * 
 * @brief Implementation of initiator_init_t.
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


#include <daemon.h>
#include <sa/states/state.h>
#include <sa/states/ike_sa_init_requested.h>
#include <utils/allocator.h>
#include <queues/jobs/retransmit_request_job.h>
#include <transforms/diffie_hellman.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/nonce_payload.h>


typedef struct private_initiator_init_t private_initiator_init_t;

/**
 * Private data of a initiator_init_t object..
 *
 */
struct private_initiator_init_t {
	/**
	 * Methods of the state_t interface.
	 */
	initiator_init_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	protected_ike_sa_t *ike_sa;
	
	/**
	 * Diffie hellman object used to generate public DH value.
	 * This objet is passed to the next state of type ike_sa_init_requested_t.
	 */
	diffie_hellman_t *diffie_hellman;
	
	/**
	 * DH group number.
	 */
	u_int16_t dh_group_number;
	
	/**
	 * DH group priority used to get dh_group_number from configuration manager.
	 * This priority is passed to the next state of type ike_sa_init_requested_t.
	 */
	u_int16_t dh_group_priority;
	
	/**
	 * Sent nonce.
	 * This nonce is passed to the next state of type ike_sa_init_requested_t.
	 */
	chunk_t sent_nonce;

	/**
	 * Logger used to log :-)
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
	
	/**
	 * Builds the IKE_SA_INIT request message.
	 * 
	 * @param this		calling object
	 * @param message	the created message will be stored at this location
	 */
	void (*build_ike_sa_init_request) (private_initiator_init_t *this, message_t **message);
	
	/**
	 * Builds the SA payload for this state.
	 * 
	 * @param this		calling object
	 * @param payload	The generated SA payload object of type ke_payload_t is 
	 * 					stored at this location.
	 */
	void (*build_sa_payload) (private_initiator_init_t *this, payload_t **payload);

	/**
	 * Builds the KE payload for this state.
	 * 
	 * @param this		calling object
	 * @param payload	The generated KE payload object of type ke_payload_t is 
	 * 					stored at this location.
	 */
	void (*build_ke_payload) (private_initiator_init_t *this, payload_t **payload);
	
	/**
	 * Builds the NONCE payload for this state.
	 * 
	 * @param this		calling object
	 * @param payload	The generated NONCE payload object of type ke_payload_t is 
	 * 					stored at this location.
	 */
	void (*build_nonce_payload) (private_initiator_init_t *this, payload_t **payload);	
	
	/**
	 * Destroy function called internally of this class after state change succeeded.
	 * 
	 * This destroy function does not destroy objects which were passed to the new state.
	 * 
	 * @param this		calling object
	 */
	void (*destroy_after_state_change) (private_initiator_init_t *this);
};

/**
 * Implementation of initiator_init_t.initiate_connection.
 */
static status_t initiate_connection (private_initiator_init_t *this, char *name)
{
	init_config_t *init_config;
	sa_config_t *sa_config;
	status_t status;
	
	this->logger->log(this->logger, CONTROL, "Initializing connection %s",name);
	
	status = charon->configuration_manager->get_init_config_for_name(charon->configuration_manager,name,&init_config);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR | MORE, "Could not retrieve INIT configuration informations for %s",name);
		return DELETE_ME;
	}
	
	this->ike_sa->set_init_config(this->ike_sa,init_config);
	
	status = charon->configuration_manager->get_sa_config_for_name(charon->configuration_manager,name,&sa_config);
	
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR | MORE, "Could not retrieve SA configuration informations for %s",name);
		return DELETE_ME;
	}
	
	this->ike_sa->set_sa_config(this->ike_sa,sa_config);
	
	/* host informations are read from configuration */	
	this->ike_sa->set_other_host(this->ike_sa,init_config->get_other_host_clone(init_config));
	this->ike_sa->set_my_host(this->ike_sa,init_config->get_my_host_clone(init_config));
	
	this->dh_group_number = init_config->get_dh_group_number(init_config,this->dh_group_priority);
	if (this->dh_group_number == MODP_UNDEFINED)
	{
		this->logger->log(this->logger, ERROR | MORE, "Diffie hellman group could not be  retrieved with priority %d", this->dh_group_priority);
		return DELETE_ME;
	}
	
	/* next step is done in retry_initiate_connection */
	return this->public.retry_initiate_connection(&(this->public),this->dh_group_priority);
}

/**
 * Implementation of initiator_init_t.retry_initiate_connection.
 */
status_t retry_initiate_connection (private_initiator_init_t *this, int dh_group_priority)
{
	ike_sa_init_requested_t *next_state;
	init_config_t *init_config;
	randomizer_t *randomizer;
	message_t *message;
	status_t status;
	ike_sa_id_t *ike_sa_id;
	
	this->dh_group_priority = dh_group_priority;
		
	init_config = this->ike_sa->get_init_config(this->ike_sa);
	
	ike_sa_id = this->ike_sa->public.get_id(&(this->ike_sa->public));
	ike_sa_id->set_responder_spi(ike_sa_id,0);
	
	this->dh_group_number = init_config->get_dh_group_number(init_config,dh_group_priority);
	if (this->dh_group_number == MODP_UNDEFINED)
	{
		this->logger->log(this->logger, ERROR | MORE, "Diffie hellman group could not be retrieved with priority %d", dh_group_priority);
		return DELETE_ME;
	}
	
	this->diffie_hellman = diffie_hellman_create(this->dh_group_number);

	this->logger->log(this->logger, CONTROL|MOST, "Get pseudo random bytes for nonce");
	randomizer = this->ike_sa->get_randomizer(this->ike_sa);
	
	allocator_free_chunk(&(this->sent_nonce));
	
	randomizer->allocate_pseudo_random_bytes(randomizer, NONCE_SIZE, &(this->sent_nonce));

	this->logger->log(this->logger, RAW|MOST, "Nonce",&(this->sent_nonce));

	this->build_ike_sa_init_request (this,&message);

	/* message can now be sent (must not be destroyed) */
	status = this->ike_sa->send_request(this->ike_sa, message);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not send request message");
		message->destroy(message);
		return DELETE_ME;
	}

	/* state can now be changed */
	this->logger->log(this->logger, CONTROL|MOST, "Create next state object");
	next_state = ike_sa_init_requested_create(this->ike_sa, this->dh_group_priority, this->diffie_hellman, this->sent_nonce);

	/* state can now be changed */ 
	this->ike_sa->set_new_state(this->ike_sa,(state_t *) next_state);

	/* state has NOW changed :-) */
	this->logger->log(this->logger, CONTROL|MORE, "Changed state of IKE_SA from %s to %s", mapping_find(ike_sa_state_m,INITIATOR_INIT),mapping_find(ike_sa_state_m,IKE_SA_INIT_REQUESTED) );
	
	this->logger->log(this->logger, CONTROL|MOST, "Destroy old sate object");
	this->destroy_after_state_change(this);
	return SUCCESS;
}

/**
 * implements private_initiator_init_t.build_ike_sa_init_request
 */
static void build_ike_sa_init_request (private_initiator_init_t *this, message_t **request)
{
	payload_t *payload;
	message_t *message;
	
	/* going to build message */
	this->logger->log(this->logger, CONTROL|MOST, "Going to build message");
	this->ike_sa->build_message(this->ike_sa, IKE_SA_INIT, TRUE, &message);
	
	/* build SA payload */		
	this->build_sa_payload(this, &payload);
	this->logger->log(this->logger, CONTROL|MOST, "add SA payload to message");
	message->add_payload(message, payload);
	
	/* build KE payload */
	this->build_ke_payload(this, &payload);
	this->logger->log(this->logger, CONTROL|MOST, "add KE payload to message");
	message->add_payload(message, payload);
	
	/* build Nonce payload */
	this->build_nonce_payload(this, &payload);
	this->logger->log(this->logger, CONTROL|MOST, "add nonce payload to message");
	message->add_payload(message, payload);
	
	*request = message;
}

/**
 * implements private_initiator_init_t.build_sa_payload
 */
static void build_sa_payload(private_initiator_init_t *this, payload_t **payload)
{
	sa_payload_t* sa_payload;
	size_t proposal_count;
	ike_proposal_t *proposals;
	init_config_t *init_config;
	
	this->logger->log(this->logger, CONTROL|MORE, "building sa payload");
	
	init_config = this->ike_sa->get_init_config(this->ike_sa);

	proposal_count = init_config->get_proposals(init_config,&proposals);
	
	sa_payload = sa_payload_create_from_ike_proposals(proposals,proposal_count);	

	allocator_free(proposals);
	*payload = (payload_t *) sa_payload;	
}

/**
 * implements private_initiator_init_t.build_ke_payload
 */
static void build_ke_payload(private_initiator_init_t *this, payload_t **payload)
{
	ke_payload_t *ke_payload;
	chunk_t key_data;
	
	this->logger->log(this->logger, CONTROL|MORE, "building ke payload");
	
	this->diffie_hellman->get_my_public_value(this->diffie_hellman,&key_data);

	ke_payload = ke_payload_create();
	ke_payload->set_dh_group_number(ke_payload, this->dh_group_number);
	ke_payload->set_key_exchange_data(ke_payload, key_data);
	
	allocator_free_chunk(&key_data);
	*payload = (payload_t *) ke_payload;
}

/**
 * implements private_initiator_init_t.build_nonce_payload
 */
static void build_nonce_payload(private_initiator_init_t *this, payload_t **payload)
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
static status_t process_message(private_initiator_init_t *this, message_t *message)
{
	this->logger->log(this->logger, ERROR|MORE, "In state INITIATOR_INIT no message is processed");
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
static void destroy(private_initiator_init_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy initiator_init_t state object");

	/* destroy stored proposal */
	this->logger->log(this->logger, CONTROL | MOST, "Destroy stored proposals");

	/* destroy diffie hellman object */
	if (this->diffie_hellman != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy diffie_hellman_t object");
		this->diffie_hellman->destroy(this->diffie_hellman);
	}
	if (this->sent_nonce.ptr != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Free memory of sent nonce");
		allocator_free(this->sent_nonce.ptr);
	}
	allocator_free(this);
}

/**
 * Implements private_initiator_init_t.destroy_after_state_change
 */
static void destroy_after_state_change (private_initiator_init_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy initiator_init_t state object");
	
	/* destroy stored proposal */
	this->logger->log(this->logger, CONTROL | MOST, "Destroy stored proposals");
	allocator_free(this);
}

/* 
 * Described in header.
 */
initiator_init_t *initiator_init_create(protected_ike_sa_t *ike_sa)
{
	private_initiator_init_t *this = allocator_alloc_thing(private_initiator_init_t);

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* public functions */
	this->public.initiate_connection = (status_t (*)(initiator_init_t *, char *)) initiate_connection;
	this->public.retry_initiate_connection = (status_t (*)(initiator_init_t *, int )) retry_initiate_connection;
	
	/* private functions */
	this->destroy_after_state_change = destroy_after_state_change;
	this->build_ike_sa_init_request = build_ike_sa_init_request;
	this->build_nonce_payload = build_nonce_payload;
	this->build_sa_payload = build_sa_payload;
	this->build_ke_payload = build_ke_payload;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->dh_group_priority = 1;
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	this->sent_nonce = CHUNK_INITIALIZER;

	return &(this->public);
}
