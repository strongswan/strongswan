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
#include "states/initiator_init.h"
#include "states/responder_init.h"




/**
 * @brief implements function process_message of protected_ike_sa_t
 */
static status_t process_message (protected_ike_sa_t *this, message_t *message)
{	
	u_int32_t message_id;
	exchange_type_t exchange_type;
	bool is_request;
	status_t status;
	state_t *new_state;
	
	/* we must process each request or response from remote host */

	/* find out type of message (request or response) */
	is_request = message->get_request(message);
	exchange_type = message->get_exchange_type(message);

	this->logger->log(this->logger, CONTROL|MORE, "Process %s message of exchange type %s",(is_request) ? "REQUEST" : "RESPONSE",mapping_find(exchange_type_m,exchange_type));

	message_id = message->get_message_id(message);

	/* 
	 * It has to be checked, if the message has to be resent cause of lost packets!
	 */
	if (is_request && ( message_id == (this->message_id_in - 1)))
	{
		/* message can be resent ! */
		this->logger->log(this->logger, CONTROL|MORE, "Resent message detected. Send stored reply");
		return (this->resend_last_reply(this));
	}
	
	/* Now, the message id is checked for request AND reply */
	if (is_request)
	{
		/* In a request, the message has to be this->message_id_in (other case is already handled) */
		if (message_id != this->message_id_in)
		{
			this->logger->log(this->logger, ERROR | MORE, "Message request with message id %d received, but %d expected",message_id,this->message_id_in);
			return FAILED;
		}
	}
	else
	{
		/* In a reply, the message has to be this->message_id_out -1 cause it is the reply to the last sent message*/
		if (message_id != (this->message_id_out - 1))
		{
			this->logger->log(this->logger, ERROR | MORE, "Message reply with message id %d received, but %d expected",message_id,this->message_id_in);
			return FAILED;
		}
	}
	
	/* now the message is processed by the current state object */
	status = this->current_state->process_message(this->current_state,message,&new_state);

	if (status == SUCCESS)
	{
		this->current_state = new_state;
	}
	return status;
}

/**
 * @brief Implements function build_message of protected_ike_sa_t.
 */
static status_t build_message(protected_ike_sa_t *this, exchange_type_t type, bool request, message_t **message)
{
	status_t status;
	message_t *new_message; 
	host_t *source, *destination;

	this	->logger->log(this->logger, CONTROL|MORE, "build empty message");	
	new_message = message_create();	
	if (new_message == NULL)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: could not create empty message object");	
		return OUT_OF_RES;
	}
	
	status  = this->me.host->clone(this->me.host, &source);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: could not clone my host information");
		new_message->destroy(new_message);
		return status;	
	}
	status = this->other.host->clone(this->other.host, &destination);	
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: could not clone other host information");
		source->destroy(source);
		new_message->destroy(new_message);
		return status;	
	}
	
	new_message->set_source(new_message, source);
	new_message->set_destination(new_message, destination);
	
	new_message->set_exchange_type(new_message, type);
	new_message->set_request(new_message, request);
	
	new_message->set_message_id(new_message, (request) ? this->message_id_out : this->message_id_in);

	status = new_message->set_ike_sa_id(new_message, this->ike_sa_id);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: could not set ike_sa_id of message");
		new_message->destroy(new_message);
		return status;
	}
	
	*message = new_message;
	
	return SUCCESS;
}

/**
 * @brief implements function process_configuration of protected_ike_sa_t
 */
static status_t initialize_connection(protected_ike_sa_t *this, char *name)
{
	/* work is done in state object of type INITIATOR_INIT */
	initiator_init_t *current_state;
	status_t status;
	state_t *new_state;
	
	if (this->current_state->get_state(this->current_state) != INITIATOR_INIT)
	{
		return FAILED;
	}
	
	current_state = (initiator_init_t *) this->current_state;
	
	status = current_state->initiate_connection(current_state,name,&new_state);
	
	if (status == SUCCESS)
	{
		this->current_state = new_state;
	}
	else
	{
		this->create_delete_job(this);
	}
	return status;
}

/**
 * @brief implements function protected_ike_sa_t.get_id
 */
static ike_sa_id_t* get_id(protected_ike_sa_t *this)
{
	return this->ike_sa_id;
}

/**
 * @brief implements function resend_last_reply of protected_ike_sa_t
 */
status_t resend_last_reply (protected_ike_sa_t *this)
{
	packet_t *packet;
	status_t status;
	
	status = this->last_responded_message->generate(this->last_responded_message, &packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not generate message to resent");
		return status;
	}
	
	status = global_send_queue->add(global_send_queue, packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not add packet to send queue");
		packet->destroy(packet);
		return status;
	}		
	return SUCCESS;
}

status_t create_delete_job (protected_ike_sa_t *this)
{
	job_t *delete_job;
	status_t status;

	this->logger->log(this->logger, CONTROL | MORE, "Going to create job to delete this IKE_SA");

	delete_job = (job_t *) delete_ike_sa_job_create(this->ike_sa_id);
	if (delete_job == NULL)
	{
 		this->logger->log(this->logger, ERROR, "Job to delete IKE SA could not be created");
 		return FAILED;
	}
	
	status = global_job_queue->add(global_job_queue,delete_job);
	if (status != SUCCESS)
	{
 		this->logger->log(this->logger, ERROR, "%s Job to delete IKE SA could not be added to job queue",mapping_find(status_m,status));
 		delete_job->destroy_all(delete_job);
 		return status;
	}
	return SUCCESS;
}

/**
 * @brief implements function destroy of protected_ike_sa_t
 */
static status_t destroy (protected_ike_sa_t *this)
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

	if (this->me.host != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy host informations of me");
		this->me.host->destroy(this->me.host);
	}
	
	if (this->other.host != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy host informations of other");
		this->other.host->destroy(this->other.host);
	}
	
	this->logger->log(this->logger, CONTROL | MOST, "Destroy current state object");
	this->current_state->destroy(this->current_state);
	
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
	protected_ike_sa_t *this = allocator_alloc_thing(protected_ike_sa_t);
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
	this->build_message = build_message;
	this->resend_last_reply = resend_last_reply;
	this->create_delete_job = create_delete_job;

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
	this->last_requested_message = NULL;
	this->last_responded_message = NULL;
	this->message_id_out = 0;
	this->message_id_in = 0;


	/* at creation time, IKE_SA is in a initiator state */
	if (ike_sa_id->is_initiator(ike_sa_id))
	{
		this->current_state = (state_t *) initiator_init_create(this);
	}
	else
	{
		this->current_state = (state_t *) responder_init_create(this);
	}
	
	if (this->current_state == NULL)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: Could not create state object");
		this->child_sas->destroy(this->child_sas);
		this->ike_sa_id->destroy(this->ike_sa_id);
		global_logger_manager->destroy_logger(global_logger_manager,this->logger);
		this->randomizer->destroy(this->randomizer);
		allocator_free(this);
	}


	return &(this->public);
}
