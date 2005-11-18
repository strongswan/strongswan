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
 * 
 * This implementation supports only window size 1
 */
#define WINDOW_SIZE 1

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
	 * contains the last X sent messages
	 * 
	 * X is windows size (here 1)
	 */
	linked_list_t *sent_messages;	
	
	struct {
		host_t *host;
	} me;
	
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
		 * 
		 */
		 chunk_t sent_nonce;
		/**
		 * 
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
	this->logger->log(this->logger, CONTROL|MORE, "Process message of exchange type %s",
						mapping_find(exchange_type_m,message->get_exchange_type(message)));
	
	/* check message id */

//	message_id = message->get_message_id(message);
//	if (message_id < (message_id_in - WINDOW_SIZE))
//	{
//		this->logger->log(this->logger, ERROR, "message cause of message id not handled");
//		/* message is to old */
//		return FAILED;
//	}
//	if (message_id > (message_id_in))
//	{
//		this->logger->log(this->logger, ERROR, "message id %d not as expected %d",message_id,message_id_in);
//		/* message is to old */
//		return FAILED;
//	}
//	
//	
//	
//	message->get_exchange_type(message);
	
	
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
	
	new_message->set_message_id(new_message, this->message_id_in);
	
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

	if (	this->sent_messages->get_count(this->sent_messages) >= WINDOW_SIZE)
	{
		message_t *removed_message;
		/* destroy message */
		this->sent_messages->remove_last(this->sent_messages,(void **)&removed_message);
		removed_message->destroy(removed_message);
	}
	
	status = this->sent_messages->insert_first(this->sent_messages,(void *) message);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not store last received message");
		message->destroy(message);
		return status;
	}

	/* message counter can no be increased */
	this->message_id_in++;
	
	/* states has NOW changed :-) */
	this->state = IKE_SA_INIT_REQUESTED;

	return SUCCESS;
}

static status_t transto_ike_sa_init_responded(private_ike_sa_t *this, message_t *message)
{
	status_t status;
	linked_list_iterator_t *payloads;
	message_t *respond;
	
	status = message->parse_body(message);
	if (status != SUCCESS)
	{
		return status;	
	}
	

	
	
	
	status = message->get_payload_iterator(message, &payloads);
	if (status != SUCCESS)
	{
		respond->destroy(respond);
		return status;	
	}
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)payload);
		switch (payload->get_type(payload))
		{
			case SECURITY_ASSOCIATION:
			{
				sa_payload_t *sa_payload;
				linked_list_iterator_t *proposals;
				
				sa_payload = (sa_payload_t*)payload;
				status = sa_payload->create_proposal_substructure_iterator(sa_payload, &proposals, TRUE);
				if (status != SUCCESS)
				{
					payloads->destroy(payloads);
					return status;
				}
				//global_configuration_manager->select_proposals_for_host
				
				break;
			}
			case KEY_EXCHANGE:
			{
				break;
			}
			case NONCE:
			{
				break;
			}
			default:
			{
				
			}
				
		}
			
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

static status_t transto_ike_auth_requested(private_ike_sa_t *this, message_t *message)
{
	return SUCCESS;
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
	/* destroy child sa's */
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
	this->ike_sa_id->destroy(this->ike_sa_id);

	/* destroy stored sent messages */
	while (this->sent_messages->get_count(this->sent_messages) > 0)
	{
		message_t *message;
		if (this->sent_messages->remove_first(this->sent_messages,(void **) &message) != SUCCESS)
		{
			break;
		}
		message->destroy(message);
	}
	this->sent_messages->destroy(this->sent_messages);
	
	this->randomizer->destroy(this->randomizer);
	if (this->ike_sa_init_data.diffie_hellman != NULL)
	{
		this->ike_sa_init_data.diffie_hellman->destroy(this->ike_sa_init_data.diffie_hellman);
	}
	if (this->ike_sa_init_data.sent_nonce.ptr != NULL)
	{
		allocator_free_chunk(this->ike_sa_init_data.sent_nonce);		
	}
	if (this->ike_sa_init_data.received_nonce.ptr != NULL)
	{
		allocator_free_chunk(this->ike_sa_init_data.received_nonce);
	}
	
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
	if (ike_sa_id->clone(ike_sa_id,&(this->ike_sa_id)) != SUCCESS)
	{
		allocator_free(this);
		return NULL;
	}
	this->child_sas = linked_list_create();
	if (this->child_sas == NULL)
	{
		this->ike_sa_id->destroy(this->ike_sa_id);
		allocator_free(this);
		return NULL;
	}
	this->randomizer = randomizer_create();
	if (this->randomizer == NULL)
	{
		this->child_sas->destroy(this->child_sas);
		this->ike_sa_id->destroy(this->ike_sa_id);
		allocator_free(this);
	}
	this->sent_messages = linked_list_create();
	if (this->sent_messages == NULL)
	{
		this->randomizer->destroy(this->randomizer);
		this->child_sas->destroy(this->child_sas);
		this->ike_sa_id->destroy(this->ike_sa_id);
		allocator_free(this);
	}
	this->logger = global_logger_manager->create_logger(global_logger_manager, IKE_SA, NULL);
	if (this->logger ==  NULL)
	{
		this->randomizer->destroy(this->randomizer);
		this->child_sas->destroy(this->child_sas);
		this->ike_sa_id->destroy(this->ike_sa_id);
		this->sent_messages->destroy(this->sent_messages);
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
	this->message_id_out = 0;
	this->message_id_in = 0;


	/* at creation time, IKE_SA isn't in a specific state */
	this->state = NO_STATE;

	return (&this->public);
}
