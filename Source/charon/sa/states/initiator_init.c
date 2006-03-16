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
	 * This objet is passed to the next state of type IKE_SA_INIT_REQUESTED.
	 */
	diffie_hellman_t *diffie_hellman;
	
	/**
	 * Sent nonce.
	 * This nonce is passed to the next state of type IKE_SA_INIT_REQUESTED.
	 */
	chunk_t sent_nonce;

	/**
	 * Assigned logger.
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
	
	/**
	 * Builds the SA payload for this state.
	 * 
	 * @param this		calling object
	 * @param request	message_t object to add the SA payload
	 */
	void (*build_sa_payload) (private_initiator_init_t *this, message_t *request);

	/**
	 * Builds the KE payload for this state.
	 * 
	 * @param this		calling object
	 * @param request	message_t object to add the KE payload
	 */
	void (*build_ke_payload) (private_initiator_init_t *this, message_t *request);
	
	/**
	 * Builds the NONCE payload for this state.
	 * 
	 * @param this		calling object
	 * @param request	message_t object to add the NONCE payload
	 */
	void (*build_nonce_payload) (private_initiator_init_t *this,message_t *request);	
	
	/**
	 * Destroy function called internally of this class after state change to state 
	 * IKE_SA_INIT_REQUESTED succeeded.
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
static status_t initiate_connection (private_initiator_init_t *this, connection_t *connection)
{
	policy_t *policy;
	diffie_hellman_group_t dh_group;
	host_t *my_host, *other_host;
	identification_t *my_id, *other_id;
	
	my_host = connection->get_my_host(connection);
	other_host = connection->get_other_host(connection);
	my_id = connection->get_my_id(connection);
	other_id = connection->get_other_id(connection);
	
	this->logger->log(this->logger, CONTROL, "Initiating connection between %s (%s) - %s (%s)",
					  my_id->get_string(my_id), my_host->get_address(my_host),
					  other_id->get_string(other_id), other_host->get_address(other_host));
	
	this->ike_sa->set_connection(this->ike_sa, connection);
	
	/* get policy */
	policy = charon->policies->get_policy(charon->policies, my_id, other_id);
	if (policy == NULL)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "Could not get a policy for '%s - %s', aborting",
						  my_id->get_string(my_id), other_id->get_string(other_id));
		return DELETE_ME;
	}
	this->ike_sa->set_policy(this->ike_sa,policy);
	
	/* we must guess now a DH group. For that we choose our most preferred group */
	dh_group = connection->get_dh_group(connection);
	
	/* next step is done in retry_initiate_connection */
	return this->public.retry_initiate_connection(&this->public, dh_group);
}

/**
 * Implementation of initiator_init_t.retry_initiate_connection.
 */
status_t retry_initiate_connection (private_initiator_init_t *this, diffie_hellman_group_t dh_group)
{
	ike_sa_init_requested_t *next_state;
	chunk_t ike_sa_init_request_data;
	connection_t *connection;
	ike_sa_id_t *ike_sa_id;
	message_t *message;
	status_t status;
	
	if (dh_group == MODP_UNDEFINED)
	{
		this->logger->log(this->logger, AUDIT, "No DH group acceptable for initialization, Aborting");
		return DELETE_ME;
	}
	
	connection = this->ike_sa->get_connection(this->ike_sa);
	this->diffie_hellman = diffie_hellman_create(dh_group);
	ike_sa_id = this->ike_sa->public.get_id(&(this->ike_sa->public));
	ike_sa_id->set_responder_spi(ike_sa_id,0);

	/* going to build message */
	this->logger->log(this->logger, CONTROL|LEVEL2, "Going to build message");
	this->ike_sa->build_message(this->ike_sa, IKE_SA_INIT, TRUE, &message);
	
	/* build SA payload */		
	this->build_sa_payload(this, message);
	
	/* build KE payload */
	this->build_ke_payload(this, message);
	
	/* build Nonce payload */
	this->build_nonce_payload(this,message);


	/* message can now be sent (must not be destroyed) */
	status = this->ike_sa->send_request(this->ike_sa, message);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "Unable to initiate connection, could not send message. Aborting");
		message->destroy(message);
		return DELETE_ME;
	}
	
	message = this->ike_sa->get_last_requested_message(this->ike_sa);
	
	ike_sa_init_request_data = message->get_packet_data(message);

	/* state can now be changed */
	this->logger->log(this->logger, CONTROL|LEVEL2, "Create next state object");
	next_state = ike_sa_init_requested_create(this->ike_sa, this->diffie_hellman, this->sent_nonce,ike_sa_init_request_data);
	this->ike_sa->set_new_state(this->ike_sa,(state_t *) next_state);
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Destroy old sate object");
	this->destroy_after_state_change(this);
	return SUCCESS;
}

/**
 * Implementation of private_initiator_init_t.build_sa_payload.
 */
static void build_sa_payload(private_initiator_init_t *this, message_t *request)
{
	sa_payload_t* sa_payload;
	linked_list_t *proposal_list;
	connection_t *connection;
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "Building SA payload");
	
	connection = this->ike_sa->get_connection(this->ike_sa);

	proposal_list = connection->get_proposals(connection);
	
	sa_payload = sa_payload_create_from_proposal_list(proposal_list);	

	this->logger->log(this->logger, CONTROL|LEVEL2, "Add SA payload to message");
	request->add_payload(request, (payload_t *) sa_payload);
}

/**
 * Implementation of private_initiator_init_t.build_ke_payload.
 */
static void build_ke_payload(private_initiator_init_t *this, message_t *request)
{
	ke_payload_t *ke_payload;
	chunk_t key_data;
	diffie_hellman_group_t dh_group;
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "Building KE payload");
	
	this->diffie_hellman->get_my_public_value(this->diffie_hellman,&key_data);
	dh_group = this->diffie_hellman->get_dh_group(this->diffie_hellman);

	ke_payload = ke_payload_create();
	ke_payload->set_dh_group_number(ke_payload, dh_group);
	ke_payload->set_key_exchange_data(ke_payload, key_data);
	
	allocator_free_chunk(&key_data);
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Add KE payload to message");
	request->add_payload(request, (payload_t *) ke_payload);
}

/**
 * Implementation of private_initiator_init_t.build_nonce_payload.
 */
static void build_nonce_payload(private_initiator_init_t *this, message_t *request)
{
	nonce_payload_t *nonce_payload;
	randomizer_t *randomizer;
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "Building NONCE payload");
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Get pseudo random bytes for NONCE");
	randomizer = this->ike_sa->get_randomizer(this->ike_sa);
	
	randomizer->allocate_pseudo_random_bytes(randomizer, NONCE_SIZE, &(this->sent_nonce));

	this->logger->log(this->logger, RAW|LEVEL2, "Initiator NONCE",&(this->sent_nonce));
	
	nonce_payload = nonce_payload_create();
	
	nonce_payload->set_nonce(nonce_payload, this->sent_nonce);
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Add NONCE payload to message");
	request->add_payload(request, (payload_t *) nonce_payload);
}

/**
 * Implementation of state_t.process_message.
 */
static status_t process_message(private_initiator_init_t *this, message_t *message)
{
	this->logger->log(this->logger, ERROR, "In state INITIATOR_INIT, no message is processed");
	return FAILED;
}

/**
 * Implementation of state_t.get_state.
 */
static ike_sa_state_t get_state(private_initiator_init_t *this)
{
	return INITIATOR_INIT;
}

/**
 * Implementation of state_t.destroy.
 */
static void destroy(private_initiator_init_t *this)
{
	this->logger->log(this->logger, CONTROL | LEVEL3, "Going to destroy initiator_init_t state object");

	/* destroy diffie hellman object */
	if (this->diffie_hellman != NULL)
	{
		this->diffie_hellman->destroy(this->diffie_hellman);
	}
	if (this->sent_nonce.ptr != NULL)
	{
		allocator_free(this->sent_nonce.ptr);
	}
	allocator_free(this);
}

/**
 * Implementation of private_initiator_init_t.destroy_after_state_change
 */
static void destroy_after_state_change (private_initiator_init_t *this)
{
	this->logger->log(this->logger, CONTROL | LEVEL3, "Going to destroy initiator_init_t state object");
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
	this->public.initiate_connection = (status_t (*)(initiator_init_t *, connection_t*)) initiate_connection;
	this->public.retry_initiate_connection = (status_t (*)(initiator_init_t *, int )) retry_initiate_connection;
	
	/* private functions */
	this->destroy_after_state_change = destroy_after_state_change;
	this->build_nonce_payload = build_nonce_payload;
	this->build_sa_payload = build_sa_payload;
	this->build_ke_payload = build_ke_payload;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	this->sent_nonce = CHUNK_INITIALIZER;
	this->diffie_hellman = NULL;

	return &(this->public);
}
