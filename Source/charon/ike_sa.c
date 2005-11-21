/**
 * @file ike_sa.c
 *
 * @brief Class ike_sa_t. An object of this type is managed by an
 * ike_sa_manager_t object and represents an IKE_SA
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

#include "ike_sa.h"

#include "types.h"
#include "globals.h"
#include "definitions.h"
#include "utils/allocator.h"
#include "utils/linked_list.h"
#include "utils/logger_manager.h"
#include "utils/randomizer.h"
#include "transforms/diffie_hellman.h"
#include "payloads/sa_payload.h"
#include "payloads/nonce_payload.h"
#include "payloads/ke_payload.h"
#include "payloads/transform_substructure.h"
#include "payloads/transform_attribute.h"


/**
 * States in which a IKE_SA can actually be
 */
typedef enum ike_sa_state_e ike_sa_state_t;

enum ike_sa_state_e {

	/**
	 * IKE_SA is is not in a state
	 */
	NO_STATE = 1,

	/**
	 * A IKE_SA_INIT-message was sent: role initiator
	 */
	IKE_SA_INIT_REQUESTED = 2,

	/**
	 * A IKE_SA_INIT-message was replied: role responder
	 */
	IKE_SA_INIT_RESPONDED = 3,

	/**
	 * An IKE_AUTH-message was sent after a successful
	 * IKE_SA_INIT-exchange: role initiator
	 */
	IKE_AUTH_REQUESTED = 4,

	/**
	 * An IKE_AUTH-message was replied: role responder.
	 * In this state, all the informations for an IKE_SA
	 * and one CHILD_SA are known.
	 */
	IKE_SA_INITIALIZED = 5
};

/**
 * string mappings for ike_sa_state 
 */
mapping_t ike_sa_state_m[] = {
	{NO_STATE, "NO_STATE"},
	{IKE_SA_INIT_REQUESTED, "IKE_SA_INIT_REQUESTED"},
	{IKE_SA_INIT_RESPONDED, "IKE_SA_INIT_RESPONDED"},
	{IKE_AUTH_REQUESTED, "IKE_AUTH_REQUESTED"},
	{IKE_SA_INITIALIZED, "IKE_SA_INITIALIZED"},
	{MAPPING_END, NULL}
};


/**
 * Private data of an message_t object
 */
typedef struct private_ike_sa_s private_ike_sa_t;

struct private_ike_sa_s {

	/**
	 * Public part of a ike_sa_t object
	 */
	ike_sa_t public;
	
	status_t (*build_sa_payload) (private_ike_sa_t *this, sa_payload_t **payload);
	status_t (*build_ke_payload) (private_ike_sa_t *this, ke_payload_t **payload);
	status_t (*build_nonce_payload) (private_ike_sa_t *this, nonce_payload_t **payload);
	
	status_t (*build_message) (private_ike_sa_t *this, exchange_type_t type, bool request, message_t **message);
	
	
	status_t (*transto_ike_sa_init_requested) (private_ike_sa_t *this, char *name);
	status_t (*transto_ike_sa_init_responded) (private_ike_sa_t *this, message_t *message);
	status_t (*transto_ike_auth_requested) (private_ike_sa_t *this, message_t *message);

	/* Private values */
	/**
	 * Identifier for the current IKE_SA
	 */
	ike_sa_id_t *ike_sa_id;

	/**
	 * Linked List containing the child sa's of the current IKE_SA
	 */
	linked_list_t *child_sas;

	/**
	 * Current state of the IKE_SA
	 */
	ike_sa_state_t state;
	
	/**
	 * this SA's source for random data
	 */
	randomizer_t *randomizer;
	
	/**
	 * contains the last responded message
	 * 
	 */
	message_t *last_responded_message;

	/**
	 * contains the last requested message
	 * 
	 */
	message_t *last_requested_message;
	
	/**
	 * Informations of this host
	 */
	struct {
		host_t *host;
	} me;

	/**
	 * Informations of the other host
	 */	
	struct {
		host_t *host;
	} other;
	
	
	struct {
		/**
		 * Diffie Hellman object used to compute shared secret
		 */
		diffie_hellman_t *diffie_hellman;
		/**
		 * Diffie Hellman group number
		 */
		u_int16_t dh_group_number;	
		
		/**
		 * Priority used get matching dh_group number
		 */
		u_int16_t dh_group_priority;
		
		/**
		 * selected proposals
		 */
		linked_list_t *proposals;
		/**
		 * Sent nonce value
		 */
		 chunk_t sent_nonce;
		/**
		 * received nonce value
		 */
		 chunk_t received_nonce;
	} ike_sa_init_data;
	

	/**
	 * next message id to receive
	 */
	u_int32_t message_id_in;
	
	/**
	 * next message id to send
	 */
	u_int32_t message_id_out;
	
	/**
	 * a logger for this IKE_SA
	 */
	logger_t *logger;
};

/**
 * @brief implements function process_message of private_ike_sa_t
 */
static status_t process_message (private_ike_sa_t *this, message_t *message)
{	
	u_int32_t message_id;
	bool is_request;
	is_request = message->get_request(message);
	this->logger->log(this->logger, CONTROL|MORE, "Process %s message of exchange type %s",(is_request) ? "REQUEST" : "RESPONSE",
						mapping_find(exchange_type_m,message->get_exchange_type(message)));
	

	//message->get_exchange_type(message);
	
	
	switch (message->get_exchange_type(message))
	{
		case IKE_SA_INIT:
		{
			if (message->get_request(message)) {
				if (this->state == 	NO_STATE)
				{
					/* state transission NO_STATE => IKE_SA_INIT_RESPONDED */
					return this->transto_ike_sa_init_responded(this, message);
				}
			}
			else
			{
				if (this->state == IKE_SA_INIT_REQUESTED)
				{
					/* state transission IKE_SA_INIT_REQUESTED => IKE_AUTH_REQUESTED*/
					return this->transto_ike_auth_requested(this, message);
				}
			}
			break;
		}
		case IKE_AUTH:
		{
			/* break; */
		}
		case CREATE_CHILD_SA:
		{
			/* break; */
		}
		case INFORMATIONAL:
		{
			/* break; */
		}
		default:
		{
			this->logger->log(this->logger, ERROR, "processing %s-message not supported.",
								mapping_find(exchange_type_m,message->get_exchange_type(message)));
			return NOT_SUPPORTED;
		}
	}
	this->logger->log(this->logger, ERROR, "received %s-message in state %s, rejected.",
								mapping_find(exchange_type_m, message->get_exchange_type(message)),
								mapping_find(ike_sa_state_m, this->state));
	return INVALID_STATE;
}


static status_t build_message(private_ike_sa_t *this, exchange_type_t type, bool request, message_t **message)
{
	status_t status;
	message_t *new_message; 
	host_t *source, *destination;
	
	new_message = message_create();	
	if (new_message == NULL)
	{
		return OUT_OF_RES;
	}
	
	status  = this->me.host->clone(this->me.host, &source);
	status |= this->other.host->clone(this->other.host, &destination);	
	if (status != SUCCESS)
	{
		new_message->destroy(new_message);
		return status;	
	}
	new_message->set_source(new_message, source);
	new_message->set_destination(new_message, destination);
	
	new_message->set_exchange_type(new_message, type);
	new_message->set_request(new_message, request);
	
	if (request)
	{
		new_message->set_message_id(new_message, this->message_id_out);
	}else
	{
		new_message->set_message_id(new_message, this->message_id_in);
	}
	
	new_message->set_ike_sa_id(new_message, this->ike_sa_id);
	
	*message = new_message;
	
	return SUCCESS;
}


static status_t transto_ike_sa_init_requested(private_ike_sa_t *this, char *name)
{
	message_t *message;
	payload_t *payload;
	packet_t *packet;
	status_t status;
	
	this->logger->log(this->logger, CONTROL, "initializing connection");
		
	status = global_configuration_manager->get_local_host(global_configuration_manager, name, &(this->me.host));
	if (status != SUCCESS)
	{	
		return INVALID_ARG;
	}
	
	status = global_configuration_manager->get_remote_host(global_configuration_manager, name, &(this->other.host));
	if (status != SUCCESS)
	{	
		return INVALID_ARG;
	}
	
	status = global_configuration_manager->get_dh_group_number(global_configuration_manager, name, &(this->ike_sa_init_data.dh_group_number), this->ike_sa_init_data.dh_group_priority);
	if (status != SUCCESS)
	{	
		return INVALID_ARG;
	}
	
	this	->logger->log(this->logger, CONTROL|MORE, "create diffie hellman object");
	if (this->ike_sa_init_data.diffie_hellman != NULL)
	{
		this->logger->log(this->logger, ERROR, "Object of type diffie_hellman_t  already existing!");
		return FAILED;
	}
	this->ike_sa_init_data.diffie_hellman = diffie_hellman_create(this->ike_sa_init_data.dh_group_number);
	if (this->ike_sa_init_data.diffie_hellman == NULL)
	{
		this->logger->log(this->logger, ERROR, "Object of type diffie_hellman_t could not be created!");
		return FAILED;			
	}
	
	if (this->ike_sa_init_data.sent_nonce.ptr != NULL)
	{
		this->logger->log(this->logger, ERROR, "Nonce for IKE_SA_INIT phase already existing!");
		return FAILED;	
	}
		
	if (this->randomizer->allocate_pseudo_random_bytes(this->randomizer, 16, &(this->ike_sa_init_data.sent_nonce)) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not create nonce!");
		return OUT_OF_RES;
	}
		
	
	/* going to build message */
	
	status = this->build_message(this, IKE_SA_INIT, TRUE, &message);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not build message");
		return status;
	}

	/* build SA payload */		
	status = this->build_sa_payload(this, (sa_payload_t**)&payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not build SA payload");
		message->destroy(message);
		return status;
	}
	message->add_payload(message, payload);
	
	/* build KE payload */
	status = this->build_ke_payload(this,(ke_payload_t **) &payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not build KE payload");
		message->destroy(message);
		return status;
	}
	message->add_payload(message, payload);
	
	/* build Nonce payload */
	status = this->build_nonce_payload(this, (nonce_payload_t**)&payload);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not build NONCE payload");
		message->destroy(message);
		return status;
	}
	message->add_payload(message, payload);
	
	
	status = message->generate(message, &packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not generate message");
		message->destroy(message);
		return status;
	}
	
	status = global_send_queue->add(global_send_queue, packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not add packet to send queue");
		message->destroy(message);
		return status;
	}

	if (	this->last_requested_message != NULL)
	{
		/* destroy message */
		this->last_requested_message->destroy(this->last_requested_message);
	}

	this->last_requested_message	 = message;

	/* message counter can now be increased */
	this->message_id_out++;
	
	/* states has NOW changed :-) */
	this->state = IKE_SA_INIT_REQUESTED;

	return SUCCESS;
}

static status_t transto_ike_sa_init_responded(private_ike_sa_t *this, message_t *request)
{
	status_t status;
	linked_list_iterator_t *payloads;
	message_t *response;
	host_t *source, *destination;
	
	/* this is the first message we process, so copy host infos */
	request->get_source(request, &source);
	request->get_destination(request, &destination);
	/* we need to clone them, since we destroy the message later */
	destination->clone(destination, &(this->me.host));
	source->clone(source, &(this->other.host));
	
	/* parse incoming message */
	status = request->parse_body(request);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not parse body");
		return status;	
	}
	/* iterate over incoming payloads */
	status = request->get_payload_iterator(request, &payloads);
	if (status != SUCCESS)
	{
		request->destroy(request);
		return status;	
	}
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		
		this->logger->log(this->logger, CONTROL|MORE, "Processing payload %s", mapping_find(payload_type_m, payload->get_type(payload)));
		switch (payload->get_type(payload))
		{
			case SECURITY_ASSOCIATION:
			{
				sa_payload_t *sa_payload = (sa_payload_t*)payload;
				linked_list_iterator_t *suggested_proposals, *accepted_proposals;
				/* create a list for accepted proposals */
				if (this->ike_sa_init_data.proposals == NULL) {
					this->ike_sa_init_data.proposals = linked_list_create();
				}
				else
				{
					/** @todo destroy list contents */	
				}
				if (this->ike_sa_init_data.proposals == NULL)
				{
					payloads->destroy(payloads);
					return OUT_OF_RES;	
				}
				status = this->ike_sa_init_data.proposals->create_iterator(this->ike_sa_init_data.proposals, &accepted_proposals, FALSE);
				if (status != SUCCESS)
				{
					payloads->destroy(payloads);
					return status;	
				}
				
				/* get the list of suggested proposals */ 
				status = sa_payload->create_proposal_substructure_iterator(sa_payload, &suggested_proposals, TRUE);
				if (status != SUCCESS)
				{	
					accepted_proposals->destroy(accepted_proposals);
					payloads->destroy(payloads);
					return status;
				}
				
				/* now let the configuration-manager select a subset of the proposals */
				status = global_configuration_manager->select_proposals_for_host(global_configuration_manager,
									this->other.host, suggested_proposals, accepted_proposals);
				if (status != SUCCESS)
				{
					suggested_proposals->destroy(suggested_proposals);
					accepted_proposals->destroy(accepted_proposals);
					payloads->destroy(payloads);
					return status;
				}
									
				suggested_proposals->destroy(suggested_proposals);
				accepted_proposals->destroy(accepted_proposals);
				
				/* ok, we have what we need for sa_payload */
				break;
			}
			case KEY_EXCHANGE:
			{
				ke_payload_t *ke_payload = (ke_payload_t*)payload;
				diffie_hellman_t *dh;
				diffie_hellman_group_t group;
				bool allowed_group;
				
				group = ke_payload->get_dh_group_number(ke_payload);
				
				status = global_configuration_manager->is_dh_group_allowed_for_host(global_configuration_manager,
								this->other.host, group, &allowed_group);
				if (status != SUCCESS)
				{
					payloads->destroy(payloads);
					return status;
				}
				if (!allowed_group)
				{
					/** @todo info reply */	
				}
				
				dh = diffie_hellman_create(group);
				if (dh == NULL)
				{
					payloads->destroy(payloads);
					return OUT_OF_RES;
				}
				
				status = dh->set_other_public_value(dh, ke_payload->get_key_exchange_data(ke_payload));
				if (status != SUCCESS)
				{
					dh->destroy(dh);
					payloads->destroy(payloads);
					return OUT_OF_RES;
				}
				/** @todo destroy if there is already one */
				this->ike_sa_init_data.diffie_hellman = dh;
				break;
			}
			case NONCE:
			{
				nonce_payload_t *nonce_payload = (nonce_payload_t*)payload;
				chunk_t nonce;
				
				nonce_payload->get_nonce(nonce_payload, &nonce);
				/** @todo free if there is already one */
				this->ike_sa_init_data.received_nonce.ptr = allocator_clone_bytes(nonce.ptr, nonce.len);
				this->ike_sa_init_data.received_nonce.len = nonce.len;
				if (this->ike_sa_init_data.received_nonce.ptr == NULL)
				{
					payloads->destroy(payloads);
					return OUT_OF_RES;
				}
				break;
			}
			default:
			{
				/** @todo handle */
			}
				
		}
			
	}
	payloads->destroy(payloads);
	
	printf("done.\n");

	/* set up the reply */
	status = this->build_message(this, IKE_SA_INIT, FALSE, &response);
	if (status != SUCCESS)
	{
		return status;	
	}
	
	
	
	
	/*
	job_t *delete_job;
	delete_job = (job_t *) delete_ike_sa_job_create(this->ike_sa_id);
	if (delete_job == NULL)
	{
 		this->logger->log(this->logger, ERROR, "Job to delete IKE SA could not be created");
	}
	
	status = global_job_queue->add(global_job_queue,delete_job);
	if (status != SUCCESS)
	{
 		this->logger->log(this->logger, ERROR, "%s Job to delete IKE SA could not be added to job queue",mapping_find(status_m,status));
 		delete_job->destroy_all(delete_job);
	}*/
	return SUCCESS;
}

static status_t transto_ike_auth_requested(private_ike_sa_t *this, message_t *response)
{	
	status_t status;
	linked_list_iterator_t *payloads;

	
	/* parse incoming message */
	status = response->parse_body(response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not parse body");
		return status;	
	}
	/* iterate over incoming payloads */
	status = response->get_payload_iterator(response, &payloads);
	if (status != SUCCESS)
	{
		response->destroy(response);
		return status;	
	}
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		
		this->logger->log(this->logger, CONTROL|MORE, "Processing payload %s", mapping_find(payload_type_m, payload->get_type(payload)));
		switch (payload->get_type(payload))
		{
//			case SECURITY_ASSOCIATION:
//			{
//				sa_payload_t *sa_payload = (sa_payload_t*)payload;
//				linked_list_iterator_t *suggested_proposals, *accepted_proposals;
//				/* create a list for accepted proposals */
//				if (this->ike_sa_init_data.proposals == NULL) {
//					this->ike_sa_init_data.proposals = linked_list_create();
//				}
//				else
//				{
//					/** @todo destroy list contents */	
//				}
//				if (this->ike_sa_init_data.proposals == NULL)
//				{
//					payloads->destroy(payloads);
//					return OUT_OF_RES;	
//				}
//				status = this->ike_sa_init_data.proposals->create_iterator(this->ike_sa_init_data.proposals, &accepted_proposals, FALSE);
//				if (status != SUCCESS)
//				{
//					payloads->destroy(payloads);
//					return status;	
//				}
//				
//				/* get the list of suggested proposals */ 
//				status = sa_payload->create_proposal_substructure_iterator(sa_payload, &suggested_proposals, TRUE);
//				if (status != SUCCESS)
//				{	
//					accepted_proposals->destroy(accepted_proposals);
//					payloads->destroy(payloads);
//					return status;
//				}
//				
//				/* now let the configuration-manager select a subset of the proposals */
//				status = global_configuration_manager->select_proposals_for_host(global_configuration_manager,
//									this->other.host, suggested_proposals, accepted_proposals);
//				if (status != SUCCESS)
//				{
//					suggested_proposals->destroy(suggested_proposals);
//					accepted_proposals->destroy(accepted_proposals);
//					payloads->destroy(payloads);
//					return status;
//				}
//									
//				suggested_proposals->destroy(suggested_proposals);
//				accepted_proposals->destroy(accepted_proposals);
//				
//				/* ok, we have what we need for sa_payload */
//				break;
//			}
			case KEY_EXCHANGE:
			{
				ke_payload_t *ke_payload = (ke_payload_t*)payload;
				diffie_hellman_t *dh;
				chunk_t shared_secret;
				
				dh = this->ike_sa_init_data.diffie_hellman;
				
				

				
				status = dh->set_other_public_value(dh, ke_payload->get_key_exchange_data(ke_payload));
				if (status != SUCCESS)
				{
					dh->destroy(dh);
					payloads->destroy(payloads);
					return OUT_OF_RES;
				}
				
				status = dh->get_shared_secret(dh, &shared_secret);
				
				this->logger->log_chunk(this->logger, RAW, "Shared secret", &shared_secret);
				
				break;
			}
			case NONCE:
			{
				nonce_payload_t *nonce_payload = (nonce_payload_t*)payload;
				chunk_t nonce;
				
				nonce_payload->get_nonce(nonce_payload, &nonce);
				/** @todo free if there is already one */
				this->ike_sa_init_data.received_nonce.ptr = allocator_clone_bytes(nonce.ptr, nonce.len);
				this->ike_sa_init_data.received_nonce.len = nonce.len;
				if (this->ike_sa_init_data.received_nonce.ptr == NULL)
				{
					payloads->destroy(payloads);
					return OUT_OF_RES;
				}
				break;
			}
			default:
			{
				/** @todo handle */
			}
				
		}
			
	}
	payloads->destroy(payloads);
	
	printf("done.\n");

	/* set up the reply */
	status = this->build_message(this, IKE_SA_INIT, FALSE, &response);
	if (status != SUCCESS)
	{
		return status;	
	}
	
	
	
}

/**
 * @brief implements function process_configuration of private_ike_sa_t
 */
static status_t initialize_connection(private_ike_sa_t *this, char *name)
{
	/* work is done in transto_ike_sa_init_requested */
	return (this->transto_ike_sa_init_requested(this,name));
}

/**
 * @brief implements function private_ike_sa_t.get_id
 */
static ike_sa_id_t* get_id(private_ike_sa_t *this)
{
	return this->ike_sa_id;
}

/**
 * implements private_ike_sa_t.build_sa_payload
 */
static status_t build_sa_payload(private_ike_sa_t *this, sa_payload_t **payload)
{
	sa_payload_t* sa_payload;
	linked_list_iterator_t *iterator;
	status_t status;

	this->logger->log(this->logger, CONTROL|MORE, "building sa payload");
	
	sa_payload = sa_payload_create();
	if (sa_payload == NULL)
	{
		return OUT_OF_RES;
	}
	status = sa_payload->create_proposal_substructure_iterator(sa_payload, &iterator, FALSE);
	if (status != SUCCESS)
	{
		sa_payload->destroy(sa_payload);
		return status;
	}
	status = global_configuration_manager->get_proposals_for_host(global_configuration_manager, this->other.host, iterator);
	if (status != SUCCESS)
	{
		sa_payload->destroy(sa_payload);
		return status;
	}
	
	*payload = sa_payload;
	
	return SUCCESS;
}

static status_t build_ke_payload(private_ike_sa_t *this, ke_payload_t **payload)
{
	ke_payload_t *ke_payload;
	chunk_t key_data;
	status_t status;

	this->logger->log(this->logger, CONTROL|MORE, "building ke payload");
	
	if (this->state != NO_STATE)
	{
		this->logger->log(this->logger, ERROR, "KE payload in state %s not supported",mapping_find(ike_sa_state_m,this->state));
		return FALSE;
	}
	
	switch(this->ike_sa_id->is_initiator(this->ike_sa_id))
	{
		case TRUE:
		{
			this	->logger->log(this->logger, CONTROL|MORE, "get public dh value to send in ke payload");
			status = this->ike_sa_init_data.diffie_hellman->get_my_public_value(this->ike_sa_init_data.diffie_hellman,&key_data);
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
		
			*payload = ke_payload;
			return SUCCESS;			
		}
		default: /* FALSE */
		{
			break;
		}
	}

	return FAILED;
}

/**
 * implements private_ike_sa_t.build_nonce_payload
 */
static status_t build_nonce_payload(private_ike_sa_t *this, nonce_payload_t **payload)
{
	nonce_payload_t *nonce_payload;
	
	this->logger->log(this->logger, CONTROL|MORE, "building nonce payload");
	nonce_payload = nonce_payload_create();
	if (nonce_payload == NULL)
	{
		return OUT_OF_RES;	
	}

	nonce_payload->set_nonce(nonce_payload, this->ike_sa_init_data.sent_nonce);
	
	*payload = nonce_payload;
	
	return SUCCESS;
}

/**
 * @brief implements function destroy of private_ike_sa_t
 */
static status_t destroy (private_ike_sa_t *this)
{
	
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy IKE_SA");
	
	/* destroy child sa's */
	this->logger->log(this->logger, CONTROL | MOST, "Destroy all child_sa's");
	while (this->child_sas->get_count(this->child_sas) > 0)
	{
		void *child_sa;
		if (this->child_sas->remove_first(this->child_sas,&child_sa) != SUCCESS)
		{
			break;
		}
		/* destroy child sa */
	}
	this->child_sas->destroy(this->child_sas);
	
	/* destroy ike_sa_id */
	this->logger->log(this->logger, CONTROL | MOST, "Destroy assigned ike_sa_id");
	this->ike_sa_id->destroy(this->ike_sa_id);

	/* destroy stored requested message */
	if (this->last_requested_message != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy last requested message");
		this->last_requested_message->destroy(this->last_requested_message);
	}
	
	/* destroy stored responded messages */
	if (this->last_responded_message != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy last responded message");
		this->last_responded_message->destroy(this->last_responded_message);
	}
	
	this->logger->log(this->logger, CONTROL | MOST, "Destroy randomizer");
	this->randomizer->destroy(this->randomizer);

	this->logger->log(this->logger, CONTROL | MOST, "Going to destroy ike_sa_init data");
	if (this->ike_sa_init_data.diffie_hellman != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy diffie hellman object");
		this->ike_sa_init_data.diffie_hellman->destroy(this->ike_sa_init_data.diffie_hellman);
	}
	if (this->ike_sa_init_data.sent_nonce.ptr != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy sent nonce data");
		allocator_free_chunk(this->ike_sa_init_data.sent_nonce);		
	}
	if (this->ike_sa_init_data.received_nonce.ptr != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy received nonce data");
		allocator_free_chunk(this->ike_sa_init_data.received_nonce);
	}
	
	this->logger->log(this->logger, CONTROL | MOST, "Destroy logger of IKE_SA");
	global_logger_manager->destroy_logger(global_logger_manager, this->logger);

	allocator_free(this);

	return SUCCESS;
}

/*
 * Described in Header
 */
ike_sa_t * ike_sa_create(ike_sa_id_t *ike_sa_id)
{
	private_ike_sa_t *this = allocator_alloc_thing(private_ike_sa_t);
	if (this == NULL)
	{
		return NULL;
	}


	/* Public functions */
	this->public.process_message = (status_t(*)(ike_sa_t*, message_t*)) process_message;
	this->public.initialize_connection = (status_t(*)(ike_sa_t*, char*)) initialize_connection;
	this->public.get_id = (ike_sa_id_t*(*)(ike_sa_t*)) get_id;
	this->public.destroy = (status_t(*)(ike_sa_t*))destroy;
	
	/* private functions */
	this->build_sa_payload = build_sa_payload;
	this->build_nonce_payload = build_nonce_payload;
	this->build_ke_payload = build_ke_payload;
	this->build_message = build_message;
	this->transto_ike_sa_init_requested = transto_ike_sa_init_requested;
	this->transto_ike_sa_init_responded = transto_ike_sa_init_responded;
	this->transto_ike_auth_requested = transto_ike_auth_requested;

	

	/* initialize private fields */
	this->logger = global_logger_manager->create_logger(global_logger_manager, IKE_SA, NULL);
	if (this->logger ==  NULL)
	{
		allocator_free(this);
	}
	
	if (ike_sa_id->clone(ike_sa_id,&(this->ike_sa_id)) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: Could not clone ike_sa_id");
		global_logger_manager->destroy_logger(global_logger_manager,this->logger);
		allocator_free(this);
		return NULL;
	}
	this->child_sas = linked_list_create();
	if (this->child_sas == NULL)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: Could not create list for child_sa's");
		this->ike_sa_id->destroy(this->ike_sa_id);
		global_logger_manager->destroy_logger(global_logger_manager,this->logger);
		allocator_free(this);
		return NULL;
	}
	this->randomizer = randomizer_create();
	if (this->randomizer == NULL)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: Could not create list for child_sa's");
		this->child_sas->destroy(this->child_sas);
		this->ike_sa_id->destroy(this->ike_sa_id);
		global_logger_manager->destroy_logger(global_logger_manager,this->logger);
		allocator_free(this);
	}
	
	this->me.host = NULL;
	this->other.host = NULL;
	this->ike_sa_init_data.diffie_hellman = NULL;
	this->ike_sa_init_data.dh_group_number = 0;
	/* 1 means highest priority */
	this->ike_sa_init_data.dh_group_priority = 1;
	this->ike_sa_init_data.sent_nonce.len = 0;
	this->ike_sa_init_data.sent_nonce.ptr = NULL;
	this->ike_sa_init_data.received_nonce.len = 0;
	this->ike_sa_init_data.received_nonce.ptr = NULL;
	this->ike_sa_init_data.proposals = NULL;
	this->last_requested_message = NULL;
	this->last_responded_message = NULL;
	this->message_id_out = 0;
	this->message_id_in = 0;


	/* at creation time, IKE_SA isn't in a specific state */
	this->state = NO_STATE;

	return (&this->public);
}
