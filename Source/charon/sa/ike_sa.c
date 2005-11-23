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

#include <types.h>
#include <globals.h>
#include <definitions.h>
#include <utils/allocator.h>
#include <utils/linked_list.h>
#include <utils/logger_manager.h>
#include <utils/randomizer.h>
#include <transforms/diffie_hellman.h>
#include <transforms/prf_plus.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/transform_substructure.h>
#include <encoding/payloads/transform_attribute.h>
#include <sa/states/initiator_init.h>
#include <sa/states/responder_init.h>




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

static status_t compute_secrets (protected_ike_sa_t *this,chunk_t dh_shared_secret,chunk_t initiator_nonce, chunk_t responder_nonce)
{
	chunk_t concatenated_nonces;
	chunk_t skeyseed;
	chunk_t prf_plus_seed;
	status_t status;
	u_int64_t initiator_spi;
	u_int64_t responder_spi;
	prf_plus_t *prf_plus;
	chunk_t secrets_raw;

	/*
	 * TODO check length for specific prf's 
	 */
	concatenated_nonces.len = (initiator_nonce.len + responder_nonce.len);
	concatenated_nonces.ptr = allocator_alloc(concatenated_nonces.len);
	if (concatenated_nonces.ptr == NULL)
	{
		this->logger->log(this->logger, ERROR, "Fatal errror: Could not allocate memory for concatenated nonces");
		return FAILED;
	}
	/* first is initiator */
	memcpy(concatenated_nonces.ptr,initiator_nonce.ptr,initiator_nonce.len);
	/* second is responder */
	memcpy(concatenated_nonces.ptr + initiator_nonce.len,responder_nonce.ptr,responder_nonce.len);

	this->logger->log_chunk(this->logger, RAW, "Nonce data", &concatenated_nonces);


	/* status of set_key is not checked */
	status = this->prf->set_key(this->prf,concatenated_nonces);

	status = this->prf->allocate_bytes(this->prf,dh_shared_secret,&skeyseed);
	if (status != SUCCESS)
	{
		allocator_free_chunk(concatenated_nonces);
		this->logger->log(this->logger, ERROR, "Fatal errror: Could not allocate bytes for skeyseed");
		return status;
	}
	allocator_free_chunk(concatenated_nonces);

	prf_plus_seed.len = (initiator_nonce.len + responder_nonce.len + 16);
	prf_plus_seed.ptr = allocator_alloc(prf_plus_seed.len);
	if (prf_plus_seed.ptr == NULL)
	{
		this->logger->log(this->logger, ERROR, "Fatal errror: Could not allocate memory for prf+ seed");
		allocator_free_chunk(skeyseed);
		return FAILED;
	}
	
	/* first is initiator */
	memcpy(prf_plus_seed.ptr,initiator_nonce.ptr,initiator_nonce.len);
	/* second is responder */
	memcpy(prf_plus_seed.ptr + initiator_nonce.len,responder_nonce.ptr,responder_nonce.len);
	/* third is initiator spi */
	initiator_spi = this->ike_sa_id->get_initiator_spi(this->ike_sa_id);
	memcpy(prf_plus_seed.ptr + initiator_nonce.len + responder_nonce.len,&initiator_spi,8);
	/* fourth is responder spi */
	responder_spi = this->ike_sa_id->get_responder_spi(this->ike_sa_id);
	memcpy(prf_plus_seed.ptr + initiator_nonce.len + responder_nonce.len + 8,&responder_spi,8);
	
	this->logger->log_chunk(this->logger, PRIVATE, "Keyseed", &skeyseed);
	this->logger->log_chunk(this->logger, PRIVATE, "PRF+ Seed", &prf_plus_seed);

	this->logger->log(this->logger, CONTROL | MOST, "Set new key of prf object");
	status = this->prf->set_key(this->prf,skeyseed);
	allocator_free_chunk(skeyseed);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal errror: Could not allocate memory for prf+ seed");
		allocator_free_chunk(prf_plus_seed);
		return FAILED;
	}
	
	this->logger->log(this->logger, CONTROL | MOST, "Create new prf+ object");
	prf_plus = prf_plus_create(this->prf, prf_plus_seed);
	allocator_free_chunk(prf_plus_seed);
	if (prf_plus == NULL)
	{
		this->logger->log(this->logger, ERROR, "Fatal errror: prf+ object could not be created");
		return FAILED;
	}
	
	prf_plus->allocate_bytes(prf_plus,100,&secrets_raw);
	
	this->logger->log_chunk(this->logger, PRIVATE, "Secrets", &secrets_raw);
	
	allocator_free_chunk(secrets_raw);
	
	prf_plus->destroy(prf_plus);

	return SUCCESS;
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

	this->logger->log(this->logger, CONTROL | MOST, "Destroy secrets");
	if (this->secrets.d_key.ptr != NULL)
	{
		allocator_free(this->secrets.d_key.ptr);
	}
	if (this->secrets.ai_key.ptr != NULL)
	{
		allocator_free(this->secrets.ai_key.ptr);
	}
	if (this->secrets.ar_key.ptr != NULL)
	{
		allocator_free(this->secrets.ar_key.ptr);
	}
	if (this->secrets.ei_key.ptr != NULL)
	{
		allocator_free(this->secrets.ei_key.ptr);
	}
	if (this->secrets.er_key.ptr != NULL)
	{
		allocator_free(this->secrets.er_key.ptr);
	}
	if (this->secrets.pi_key.ptr != NULL)
	{
		allocator_free(this->secrets.pi_key.ptr);
	}
	if (this->secrets.pr_key.ptr != NULL)
	{
		allocator_free(this->secrets.pr_key.ptr);
	}
	
	if (	this->crypter_initiator != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy initiator crypter");
		this->crypter_initiator->destroy(this->crypter_initiator);
	}
	
	if (	this->crypter_responder != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy responder crypter");
		this->crypter_responder->destroy(this->crypter_responder);
	}
	
	if (	this->signer_initiator != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy initiator signer");
		this->signer_initiator->destroy(this->signer_initiator);
	}

	if (this->signer_responder != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy responder signer");
		this->signer_responder->destroy(this->signer_responder);
	}
	
	if (this->prf != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy prf");
		this->prf->destroy(this->prf);
	}
	
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
	this->compute_secrets = compute_secrets;

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
	this->secrets.d_key.ptr = NULL;
	this->secrets.d_key.len = 0;
	this->secrets.ai_key.ptr = NULL;
	this->secrets.ai_key.len = 0;
	this->secrets.ar_key.ptr = NULL;
	this->secrets.ar_key.len = 0;
	this->secrets.ei_key.ptr = NULL;	
	this->secrets.ei_key.len = 0;
	this->secrets.er_key.ptr = NULL;
	this->secrets.er_key.len = 0;
	this->secrets.pi_key.ptr = NULL;
	this->secrets.pi_key.len = 0;
	this->secrets.pr_key.ptr = NULL;
	this->secrets.pr_key.len = 0;
	this->crypter_initiator = NULL;
	this->crypter_responder = NULL;
	this->signer_initiator = NULL;
	this->signer_responder = NULL;
	this->prf = NULL;
	



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
