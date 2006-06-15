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
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <crypto/diffie_hellman.h>


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
	 * Selected proposal
	 */
	proposal_t *proposal;
	
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
	 * 						- DESTROY_ME
	 * 						- SUCCESS
	 */
	status_t (*build_sa_payload) (private_responder_init_t *this,sa_payload_t *sa_request, message_t *response);

	/**
	 * Handles received KE payload and builds the KE payload for the response.
	 * 
	 * @param this		calling object
	 * @param ke_request	The received KE payload
	 * @param response		the KE payload is added to this response message_t object.
	 * 						- DESTROY_ME
	 * 						- SUCCESS
	 */
	status_t (*build_ke_payload) (private_responder_init_t *this,ke_payload_t *ke_request, message_t *response);
	
	/**
	 * Handles received NONCE payload and builds the NONCE payload for the response.
	 * 
	 * @param this			calling object
	 * @param nonce_request	The received NONCE payload
	 * @param response		the NONCE payload is added to this response message_t object.
	 * 						- DESTROY_ME
	 * 						- SUCCESS
	 */
	status_t (*build_nonce_payload) (private_responder_init_t *this,nonce_payload_t *nonce_request, message_t *response);	
	
	/**
	 * Sends a IKE_SA_INIT reply containing a notify payload.
	 * 
	 * @param this				calling object
	 * @param notify_payload 	notify_payload to process
	 */
	status_t (*process_notify_payload) (private_responder_init_t *this, notify_payload_t *notify_payload);
	
	/**
	 * Destroy function called internally of this class after change 
	 * to state IKE_SA_INIT_RESPONDED succeeded.
	 * 
	 * This destroy function does not destroy objects which were passed to the new state.
	 * 
	 * @param this		calling object
	 */
	void (*destroy_after_state_change) (private_responder_init_t *this);

};

/**
 * Implementation of state_t.process_message.
 */
static status_t process_message(private_responder_init_t *this, message_t *message)
{
	ike_sa_init_responded_t *next_state;
	chunk_t ike_sa_init_response_data;
	chunk_t ike_sa_init_request_data;
	sa_payload_t *sa_request = NULL;
	ke_payload_t *ke_request = NULL;
	nonce_payload_t *nonce_request = NULL;
	host_t *source, *destination;
	connection_t *connection;
	iterator_t *payloads;
	message_t *response;
	status_t status;

	if (message->get_exchange_type(message) != IKE_SA_INIT)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "message of type %s not supported in state responder_init",
						  mapping_find(exchange_type_m,message->get_exchange_type(message)));
		return DESTROY_ME;
	}
	if (!message->get_request(message))
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "IKE_SA_INIT responses not allowed in state ike_sa_init_responded");
		return DESTROY_ME;
	}
	
	/* this is the first message to process, so get host infos */
	source = message->get_source(message);
	destination = message->get_destination(message);

	connection = charon->connections->get_connection_by_hosts(charon->connections, destination, source);
	if (connection == NULL)
	{
		/* no configuration matches given hosts */
		this->logger->log(this->logger, AUDIT, "IKE_SA_INIT request does not match any available connection, deleting IKE_SA");
		/* TODO: inform requestor */
		return DESTROY_ME;
	}
	this->ike_sa->set_connection(this->ike_sa,connection);
	
	/* parse incoming message */
	status = message->parse_body(message, NULL, NULL);
	if (status != SUCCESS)
	{
		if (status == NOT_SUPPORTED)
		{
			this->logger->log(this->logger, AUDIT, "IKE_SA_INIT request contains unsupported payload with critical flag set, "
													"deleting IKE_SA");
			this->ike_sa->send_notify(this->ike_sa, IKE_SA_INIT, UNSUPPORTED_CRITICAL_PAYLOAD, CHUNK_INITIALIZER);
		}
		else
		{
			this->logger->log(this->logger, AUDIT, "unable to parse IKE_SA_INIT request, deleting IKE_SA");
		}
		return DESTROY_ME;
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
				status = this->process_notify_payload(this, notify_payload);
				if (status != SUCCESS)
				{
					payloads->destroy(payloads);
					return status;	
				}
			}
			default:
			{
				this->logger->log(this->logger, ERROR|LEVEL1, "ignoring payload %s (%d)", 
									mapping_find(payload_type_m, payload->get_type(payload)), payload->get_type(payload));
				break;
			}
		}
	}
	payloads->destroy(payloads);
	
	/* check if we have all payloads */
	if (!(sa_request && ke_request && nonce_request))
	{
		this->logger->log(this->logger, AUDIT, "IKE_SA_INIT request did not contain all required payloads. deleting IKE_SA");
		return DESTROY_ME;
	}
	
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
	
	/* derive all the keys used in the IKE_SA */
	status = this->ike_sa->build_transforms(this->ike_sa, this->proposal, this->diffie_hellman, this->received_nonce, this->sent_nonce);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "transform objects could not be created from selected proposal, deleting IKE_SA");
		return DESTROY_ME;
	}
	
	/* message can now be sent (must not be destroyed) */
	status = this->ike_sa->send_response(this->ike_sa, response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "unable to send IKE_SA_INIT response, deleting IKE_SA");
		response->destroy(response);
		return DESTROY_ME;
	}

	/* state can now be changed */
	this->logger->log(this->logger, CONTROL|LEVEL2, "create next state object of type IKE_SA_INIT_RESPONDED");

	response = this->ike_sa->get_last_responded_message(this->ike_sa);
	ike_sa_init_response_data = response->get_packet_data(response);
	ike_sa_init_request_data = message->get_packet_data(message);

	next_state = ike_sa_init_responded_create(this->ike_sa, this->received_nonce, this->sent_nonce,ike_sa_init_request_data,
												ike_sa_init_response_data);
	
	/* state can now be changed */
	this->ike_sa->set_new_state(this->ike_sa, (state_t *) next_state);
	this->destroy_after_state_change(this);	
	
	return SUCCESS;
}

/**
 * Implementation of private_initiator_init_t.build_sa_payload.
 */
static status_t build_sa_payload(private_responder_init_t *this,sa_payload_t *sa_request, message_t *response)
{
	proposal_t *proposal;
	linked_list_t *proposal_list;
	connection_t *connection;
	sa_payload_t* sa_payload;
	algorithm_t *algo;

	connection = this->ike_sa->get_connection(this->ike_sa);

	this->logger->log(this->logger, CONTROL | LEVEL2, "process received SA payload");
	
	/* get the list of suggested proposals */ 
	proposal_list = sa_request->get_proposals (sa_request);

	/* select proposal */
	this->proposal = connection->select_proposal(connection, proposal_list);
	while(proposal_list->remove_last(proposal_list, (void**)&proposal) == SUCCESS)
	{
		proposal->destroy(proposal);
	}
	proposal_list->destroy(proposal_list);
	if (this->proposal == NULL)
	{
		this->logger->log(this->logger, AUDIT, "IKE_SA_INIT request did not contain any acceptable proposals, deleting IKE_SA");
		this->ike_sa->send_notify(this->ike_sa, IKE_SA_INIT, NO_PROPOSAL_CHOSEN, CHUNK_INITIALIZER);
		return DESTROY_ME;
	}
	/* get selected DH group to force policy, this is very restrictive!? */
	if (this->proposal->get_algorithm(this->proposal, DIFFIE_HELLMAN_GROUP, &algo))
	{
		this->dh_group_number = algo->algorithm;
	}
	
	this->logger->log(this->logger, CONTROL | LEVEL2, "SA Payload processed");
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "building SA payload");
	sa_payload = sa_payload_create_from_proposal(this->proposal);	
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
				
	this->logger->log(this->logger, CONTROL | LEVEL2, "process received KE payload");
	group = ke_request->get_dh_group_number(ke_request);
				
	if (group == MODP_NONE)
	{
		this->logger->log(this->logger, AUDIT, "no Diffie-Hellman group to select, deleting IKE_SA");
		return DESTROY_ME;
	}
	
	if (this->dh_group_number != group)
	{
		u_int16_t accepted_group;
		chunk_t accepted_group_chunk;
		/* group not same as selected one 
		 * Maybe key exchange payload is before SA payload */
		this->logger->log(this->logger, AUDIT, "IKE_SA_INIT request did not contain an acceptable Diffie-Hellman group, deleting IKE_SA");
		
		accepted_group = htons(this->dh_group_number);
		accepted_group_chunk.ptr = (u_int8_t*) &(accepted_group);
		accepted_group_chunk.len = 2;
		this->ike_sa->send_notify(this->ike_sa,IKE_SA_INIT,INVALID_KE_PAYLOAD,accepted_group_chunk);
		return DESTROY_ME;
	}
			
	/* create diffie hellman object to handle DH exchange */
	dh = diffie_hellman_create(group);
	if (dh == NULL)
	{
		this->logger->log(this->logger, AUDIT, "could not generate DH object with group %d, deleting IKE_SA",
							mapping_find(diffie_hellman_group_m,group) );
		return DESTROY_ME;
	}
	this->logger->log(this->logger, CONTROL | LEVEL2, "set other DH public value");
	
	dh->set_other_public_value(dh, ke_request->get_key_exchange_data(ke_request));

	this->diffie_hellman = dh;
	
	this->logger->log(this->logger, CONTROL | LEVEL2, "KE payload processed.");

	this->logger->log(this->logger, CONTROL|LEVEL2, "building KE payload");
	this->diffie_hellman->get_my_public_value(this->diffie_hellman,&key_data);

	ke_payload = ke_payload_create();
	ke_payload->set_key_exchange_data(ke_payload,key_data);
	ke_payload->set_dh_group_number(ke_payload, this->dh_group_number);
	chunk_free(&key_data);

	this->logger->log(this->logger, CONTROL|LEVEL2, "add KE payload to message");
	response->add_payload(response,(payload_t *) ke_payload);
	
	return SUCCESS;
}

/**
 * Implementation of private_responder_init_t.build_nonce_payload.
 */
static status_t build_nonce_payload(private_responder_init_t *this,nonce_payload_t *nonce_request, message_t *response)
{
	nonce_payload_t *nonce_payload;
	randomizer_t *randomizer;
	status_t status;

	this->logger->log(this->logger, CONTROL | LEVEL2, "process received NONCE payload");
	free(this->received_nonce.ptr);
	this->received_nonce = CHUNK_INITIALIZER;

	this->logger->log(this->logger, CONTROL | LEVEL2, "get NONCE value and store it");
	this->received_nonce = nonce_request->get_nonce(nonce_request);
	
	this->logger->log(this->logger, CONTROL | LEVEL2, "create new NONCE value.");	
	
	randomizer = this->ike_sa->get_randomizer(this->ike_sa);
	status = randomizer->allocate_pseudo_random_bytes(randomizer, NONCE_SIZE, &(this->sent_nonce));
	if (status != SUCCESS)
	{
		return status;
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "building NONCE payload");
	nonce_payload = nonce_payload_create();
	nonce_payload->set_nonce(nonce_payload, this->sent_nonce);
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "add NONCE payload to message");
	response->add_payload(response,(payload_t *) nonce_payload);
	
	return SUCCESS;
}

/**
 * Implementation of private_responder_init_t.process_notify_payload.
 */
static status_t process_notify_payload(private_responder_init_t *this, notify_payload_t *notify_payload)
{
	notify_message_type_t notify_message_type = notify_payload->get_notify_message_type(notify_payload);
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "process notify type %s",
						  mapping_find(notify_message_type_m, notify_message_type));
								  
	if (notify_payload->get_protocol_id(notify_payload) != PROTO_IKE)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, "notify reply not for IKE protocol.");
		return FAILED;	
	}
	switch (notify_message_type)
	{
		default:
		{
				this->logger->log(this->logger, CONTROL, "IKE_SA_INIT request contained a notify (%d), ignored.", 
									notify_message_type);
			return SUCCESS;
		}
	}	
}

/**
 * Implementation of  state_t.get_state.
 */
static ike_sa_state_t get_state(private_responder_init_t *this)
{
	return RESPONDER_INIT;
}

/**
 * Implementation of state_t.destroy.
 */
static void destroy(private_responder_init_t *this)
{
	this->logger->log(this->logger, CONTROL | LEVEL1, "going to destroy responder init state object");
	
	this->logger->log(this->logger, CONTROL | LEVEL2, "destroy nonces");
	chunk_free(&(this->sent_nonce));
	chunk_free(&(this->received_nonce));

	if (this->diffie_hellman != NULL)
	{
		this->logger->log(this->logger, CONTROL | LEVEL2, "destroy diffie_hellman_t hellman object");
		this->diffie_hellman->destroy(this->diffie_hellman);
	}
	if (this->proposal)
	{
		this->proposal->destroy(this->proposal);
	}
	this->logger->log(this->logger, CONTROL | LEVEL2, "destroy object");
	free(this);
}

/**
 * Implementation of private_responder_init_t.destroy_after_state_change
 */
static void destroy_after_state_change (private_responder_init_t *this)
{
	this->logger->log(this->logger, CONTROL | LEVEL1, "going to destroy responder_init_t state object");
	
	/* destroy diffie hellman object */
	if (this->diffie_hellman != NULL)
	{
		this->logger->log(this->logger, CONTROL | LEVEL2, "destroy diffie_hellman_t object");
		this->diffie_hellman->destroy(this->diffie_hellman);
	}
	if (this->proposal)
	{
		this->proposal->destroy(this->proposal);
	}
	
	this->logger->log(this->logger, CONTROL | LEVEL2, "destroy object");	
	free(this);
}

/* 
 * Described in header.
 */
responder_init_t *responder_init_create(protected_ike_sa_t *ike_sa)
{
	private_responder_init_t *this = malloc_thing(private_responder_init_t);

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private functions */
	this->build_sa_payload = build_sa_payload;
	this->build_ke_payload = build_ke_payload;
	this->build_nonce_payload = build_nonce_payload;
	this->destroy_after_state_change = destroy_after_state_change;
	this->process_notify_payload = process_notify_payload;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);
	this->sent_nonce = CHUNK_INITIALIZER;
	this->received_nonce = CHUNK_INITIALIZER;
	this->dh_group_number = MODP_NONE;
	this->diffie_hellman = NULL;
	this->proposal = NULL;

	return &(this->public);
}
