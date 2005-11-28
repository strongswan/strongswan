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
#include <transforms/crypters/crypter.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/transform_substructure.h>
#include <encoding/payloads/transform_attribute.h>
#include <sa/states/initiator_init.h>
#include <sa/states/responder_init.h>
#include <queues/jobs/delete_ike_sa_job.h>




typedef struct private_ike_sa_t private_ike_sa_t;

/**
 * Private data of an ike_sa_t object.
 */
struct private_ike_sa_t {

	/**
	 * Protected part of a ike_sa_t object.
	 */
	protected_ike_sa_t protected;


	/**
	 * Creates a job to delete the given IKE_SA.
	 * 
	 * @param this 				calling object
	 */
	status_t (*create_delete_job) (private_ike_sa_t *this);

	/**
	 * Resends the last sent reply.
	 * 
	 * @param this 				calling object
	 */
	status_t (*resend_last_reply) (private_ike_sa_t *this);

	/* private values */
	
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
	state_t *current_state;
	
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
	
	/**
	 * Crypter object for initiator
	 */
	crypter_t *crypter_initiator;
	
	/**
	 * Crypter object for responder
	 */
	crypter_t *crypter_responder;
	
	/**
	 * Signer object for initiator
	 */
	signer_t *signer_initiator;
	
	/**
	 * Signer object for responder
	 */
	signer_t *signer_responder;
	
	/**
	 * prf function
	 */
	prf_t *prf;
	
	
	
	/**
	 * Shared secrets
	 */
	struct {
		/**
		 * Key used for deriving other keys
		 */
		chunk_t d_key;
		
		/**
		 * Key for authenticate (initiator)
		 */
		chunk_t ai_key;
		
		/**
		 * Key for authenticate (responder)
		 */
		chunk_t ar_key;

		/**
		 * Key for encryption (initiator)
		 */
		chunk_t ei_key;	

		/**
		 * Key for encryption (responder)
		 */
		chunk_t er_key;	

		/**
		 * Key for generating auth payload (initiator)
		 */
		chunk_t pi_key;	

		/**
		 * Key for generating auth payload (responder)
		 */
		chunk_t pr_key;	

	} secrets;

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
 * Implements protected_ike_sa_t.process_message.
 */
static status_t process_message (private_ike_sa_t *this, message_t *message)
{
	u_int32_t message_id;
	exchange_type_t exchange_type;
	bool is_request;
	
	/* we must process each request or response from remote host */

	/* find out type of message (request or response) */
	is_request = message->get_request(message);
	exchange_type = message->get_exchange_type(message);

	this->logger->log(this->logger, CONTROL, "Process %s message of exchange type %s",(is_request) ? "REQUEST" : "RESPONSE",mapping_find(exchange_type_m,exchange_type));

	message_id = message->get_message_id(message);

	/* 
	 * It has to be checked, if the message has to be resent cause of lost packets!
	 */
	if (is_request && (message_id == (this->message_id_in - 1)))
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
	/* the current state does change the current change to the next one*/
	return this->current_state->process_message(this->current_state,message);
}

/**
 * Implements protected_ike_sa_t.build_message.
 */
static void build_message(private_ike_sa_t *this, exchange_type_t type, bool request, message_t **message)
{
	message_t *new_message; 
	host_t *source, *destination;

	this->logger->log(this->logger, CONTROL|MORE, "build empty message");	
	new_message = message_create();	
	
	source = this->me.host->clone(this->me.host);
	destination = this->other.host->clone(this->other.host);	

	new_message->set_source(new_message, source);
	new_message->set_destination(new_message, destination);
	new_message->set_exchange_type(new_message, type);
	new_message->set_request(new_message, request);
	new_message->set_message_id(new_message, (request) ? this->message_id_out : this->message_id_in);
	new_message->set_ike_sa_id(new_message, this->ike_sa_id);
	*message = new_message;
}

/**
 * Implements protected_ike_sa_t.process_configuration.
 */
static status_t initialize_connection(private_ike_sa_t *this, char *name)
{
	/* work is done in state object of type INITIATOR_INIT */
	initiator_init_t *current_state;
	status_t status;
	
	if (this->current_state->get_state(this->current_state) != INITIATOR_INIT)
	{
		return FAILED;
	}
	
	current_state = (initiator_init_t *) this->current_state;
	
	status = current_state->initiate_connection(current_state,name);
	
	if (status != SUCCESS)
	{
		this->create_delete_job(this);
	}
	return status;
}

/**
 * Implements protected_ike_sa_t.get_id.
 */
static ike_sa_id_t* get_id(private_ike_sa_t *this)
{
	return this->ike_sa_id;
}

/**
 * Implements protected_ike_sa_t.compute_secrets.
 */
static void compute_secrets(private_ike_sa_t *this,chunk_t dh_shared_secret,chunk_t initiator_nonce, chunk_t responder_nonce)
{
	chunk_t concatenated_nonces;
	chunk_t skeyseed;
	chunk_t prf_plus_seed;
	u_int64_t initiator_spi;
	u_int64_t responder_spi;
	prf_plus_t *prf_plus;
	
	
	/*
	 * TODO check length for specific prf's 
	 */
	concatenated_nonces.len = (initiator_nonce.len + responder_nonce.len);
	concatenated_nonces.ptr = allocator_alloc(concatenated_nonces.len);

	/* first is initiator */
	memcpy(concatenated_nonces.ptr,initiator_nonce.ptr,initiator_nonce.len);
	/* second is responder */
	memcpy(concatenated_nonces.ptr + initiator_nonce.len,responder_nonce.ptr,responder_nonce.len);

	this->logger->log_chunk(this->logger, RAW, "Nonce data", &concatenated_nonces);

	/* status of set_key is not checked */
	this->prf->set_key(this->prf,concatenated_nonces);

	this->prf->allocate_bytes(this->prf,dh_shared_secret,&skeyseed);

	allocator_free_chunk(&concatenated_nonces);

	prf_plus_seed.len = (initiator_nonce.len + responder_nonce.len + 16);
	prf_plus_seed.ptr = allocator_alloc(prf_plus_seed.len);
	
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
	
	this->logger->log_chunk(this->logger, PRIVATE | MORE, "Keyseed", &skeyseed);
	this->logger->log_chunk(this->logger, PRIVATE | MORE, "PRF+ Seed", &prf_plus_seed);

	this->logger->log(this->logger, CONTROL | MOST, "Set new key of prf object");
	this->prf->set_key(this->prf,skeyseed);
	allocator_free_chunk(&skeyseed);
 
	this->logger->log(this->logger, CONTROL | MOST, "Create new prf+ object");
	prf_plus = prf_plus_create(this->prf, prf_plus_seed);
	allocator_free_chunk(&prf_plus_seed);
	
	prf_plus->allocate_bytes(prf_plus,this->prf->get_block_size(this->prf),&(this->secrets.d_key));
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_d secret", &(this->secrets.d_key));

	prf_plus->allocate_bytes(prf_plus,this->crypter_initiator->get_block_size(this->crypter_initiator),&(this->secrets.ei_key));
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_ei secret", &(this->secrets.ei_key));
	this->crypter_initiator->set_key(this->crypter_initiator,this->secrets.ei_key);

	prf_plus->allocate_bytes(prf_plus,this->crypter_responder->get_block_size(this->crypter_responder),&(this->secrets.er_key));
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_er secret", &(this->secrets.er_key));
	this->crypter_responder->set_key(this->crypter_responder,this->secrets.er_key);

	prf_plus->allocate_bytes(prf_plus,this->signer_initiator->get_block_size(this->signer_initiator),&(this->secrets.ai_key));
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_ai secret", &(this->secrets.ai_key));
	this->signer_initiator->set_key(this->signer_initiator,this->secrets.ai_key);

	prf_plus->allocate_bytes(prf_plus,this->signer_responder->get_block_size(this->signer_responder),&(this->secrets.ar_key));
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_ar secret", &(this->secrets.ar_key));
	this->signer_responder->set_key(this->signer_responder,this->secrets.ar_key);

	prf_plus->allocate_bytes(prf_plus,this->crypter_responder->get_block_size(this->crypter_responder),&(this->secrets.pi_key));
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_pi secret", &(this->secrets.pi_key));
	
	prf_plus->allocate_bytes(prf_plus,this->crypter_responder->get_block_size(this->crypter_responder),&(this->secrets.pr_key));
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_pr secret", &(this->secrets.pr_key));
	
	prf_plus->destroy(prf_plus);
}

/**
 * Implements protected_ike_sa_t.resend_last_reply.
 */
static status_t resend_last_reply(private_ike_sa_t *this)
{
	packet_t *packet;
	status_t status;
	
	status = this->last_responded_message->generate(this->last_responded_message, NULL, NULL, &packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not generate message to resent");
		return status;
	}
	
	global_send_queue->add(global_send_queue, packet);
	return SUCCESS;
}

/**
 * Implements protected_ike_sa_t.resend_last_reply.
 */
static status_t create_delete_job(private_ike_sa_t *this)
{
	job_t *delete_job;

	this->logger->log(this->logger, CONTROL | MORE, "Going to create job to delete this IKE_SA");

	delete_job = (job_t *) delete_ike_sa_job_create(this->ike_sa_id);
	global_job_queue->add(global_job_queue,delete_job);

	return SUCCESS;
}

/**
 * Implementation of protected_ike_sa_t.set_new_state.
 */
static void set_new_state (private_ike_sa_t *this, state_t *state)
{
	this->logger->log(this->logger, ERROR, "Change current state %s to %s",mapping_find(ike_sa_state_m,this->current_state->get_state(this->current_state)),mapping_find(ike_sa_state_m,state->get_state(state)));
	this->current_state = state;
}

/**
 * Implementation of protected_ike_sa_t.get_logger.
 */
static logger_t *get_logger (private_ike_sa_t *this)
{
	return this->logger;
}

/**
 * Implementation of protected_ike_sa_t.get_my_host.
 */
static host_t *get_my_host (private_ike_sa_t *this)
{
	return this->me.host;
}

/**
 * Implementation of protected_ike_sa_t.get_other_host.
 */
static host_t *get_other_host (private_ike_sa_t *this)
{
	return this->other.host;
}

/**
 * Implementation of protected_ike_sa_t.set_my_host.
 */
static void set_my_host (private_ike_sa_t *this, host_t *my_host)
{
	if (this->me.host != NULL)
	{
		this	->logger->log(this->logger, CONTROL|MOST, "Destroy existing my host object");
		this->me.host->destroy(this->me.host);
	}
	this->me.host = my_host;
}

/**
 * Implementation of protected_ike_sa_t.set_other_host.
 */
static void set_other_host (private_ike_sa_t *this, host_t *other_host)
{
	if (this->other.host != NULL)
	{
		this	->logger->log(this->logger, CONTROL|MOST, "Destroy existing other host object");
		this->other.host->destroy(this->other.host);
	}
	this->other.host = other_host;
}

/**
 * Implementation of protected_ike_sa_t.set_prf.
 */
static status_t create_transforms_from_proposal (private_ike_sa_t *this,proposal_substructure_t *proposal)
{
	status_t status;
	u_int16_t encryption_algorithm;
	u_int16_t encryption_algorithm_key_length;
	u_int16_t integrity_algorithm;
	u_int16_t integrity_algorithm_key_length;
	u_int16_t pseudo_random_function;
	u_int16_t pseudo_random_function_key_length;
	
	this->logger->log(this->logger, CONTROL|MORE, "Going to create transform objects for proposal");
	
	this->logger->log(this->logger, CONTROL|MOST, "Get encryption transform type");
	status = proposal->get_info_for_transform_type(proposal,ENCRYPTION_ALGORITHM,&(encryption_algorithm),&(encryption_algorithm_key_length));
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR|MORE, "Could not get encryption transform type");
		return status;
	}
	this->logger->log(this->logger, CONTROL|MORE, "Encryption algorithm: %s with keylength %d",mapping_find(encryption_algorithm_m,encryption_algorithm),encryption_algorithm_key_length);
	
	this->logger->log(this->logger, CONTROL|MOST, "Get integrity transform type");
	status = proposal->get_info_for_transform_type(proposal,INTEGRITY_ALGORITHM,&(integrity_algorithm),&(integrity_algorithm_key_length));
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR|MORE, "Could not get integrity transform type");
		return status;
	}
	this->logger->log(this->logger, CONTROL|MORE, "integrity algorithm: %s with keylength %d",mapping_find(integrity_algorithm_m,integrity_algorithm),integrity_algorithm_key_length);
	
	this->logger->log(this->logger, CONTROL|MOST, "Get prf transform type");
	status = proposal->get_info_for_transform_type(proposal,PSEUDO_RANDOM_FUNCTION,&(pseudo_random_function),&(pseudo_random_function_key_length));
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR|MORE, "Could not prf transform type");
		return status;
	}
	this->logger->log(this->logger, CONTROL|MORE, "prf: %s with keylength %d",mapping_find(pseudo_random_function_m,pseudo_random_function),pseudo_random_function_key_length);
	
	if (this->prf != NULL)
	{
		this->prf->destroy(this->prf);
	}
	this->prf = prf_create(pseudo_random_function);
	if (this->prf == NULL)
	{
		this->logger->log(this->logger, ERROR|MORE, "prf not supported!");
		return FAILED;
	}
	
	if (this->crypter_initiator != NULL)
	{
		this->crypter_initiator->destroy(this->crypter_initiator);
	}
	this->crypter_initiator = crypter_create(encryption_algorithm,encryption_algorithm_key_length);
	if (this->crypter_initiator == NULL)
	{
		this->logger->log(this->logger, ERROR|MORE, "encryption algorithm not supported!");
		return FAILED;
	}

	if (this->crypter_responder != NULL)
	{
		this->crypter_responder->destroy(this->crypter_responder);
	}
	this->crypter_responder = crypter_create(encryption_algorithm,encryption_algorithm_key_length);
	if (this->crypter_responder == NULL)
	{
		this->logger->log(this->logger, ERROR|MORE, "encryption algorithm not supported!");
		return FAILED;
	}
	
	if (this->signer_initiator != NULL)
	{
		this->signer_initiator->destroy(this->signer_initiator);
	}
	this->signer_initiator = signer_create(integrity_algorithm);
	if (this->signer_initiator == NULL)
	{
		this->logger->log(this->logger, ERROR|MORE, "integrity algorithm not supported!");
		return FAILED;
	}
	
	if (this->signer_responder != NULL)
	{
		this->signer_responder->destroy(this->signer_responder);
	}
	this->signer_responder = signer_create(integrity_algorithm);
	if (this->signer_responder == NULL)
	{
		this->logger->log(this->logger, ERROR|MORE, "integrity algorithm not supported!");
		return FAILED;
	}

	return SUCCESS;
}

/**
 * Implementation of protected_ike_sa_t.get_randomizer.
 */
static randomizer_t *get_randomizer (private_ike_sa_t *this)
{
	return this->randomizer;
}

/**
 * Implementation of protected_ike_sa_t.set_last_requested_message.
 */
static status_t set_last_requested_message (private_ike_sa_t *this,message_t * message)
{
	if (this->last_requested_message != NULL)
	{
		/* destroy message */
		this->last_requested_message->destroy(this->last_requested_message);
	}

	if (message->get_message_id(message) != this->message_id_out)
	{
		this->logger->log(this->logger, CONTROL|MOST, "last requested message could not be set cause id was not as expected");
		return FAILED;
	}
	this->logger->log(this->logger, CONTROL|MOST, "replace last requested message with new one");
	this->last_requested_message = message;

	/* message counter can now be increased */
	this->logger->log(this->logger, CONTROL|MOST, "Increate message counter for outgoing messages");
	this->message_id_out++;
	return SUCCESS;	
}

/**
 * Implementation of protected_ike_sa_t.set_last_responded_message.
 */
static status_t set_last_responded_message (private_ike_sa_t *this,message_t * message)
{
	if (this->last_responded_message != NULL)
	{
		/* destroy message */
		this->last_responded_message->destroy(this->last_responded_message);
	}
	if (message->get_message_id(message) != this->message_id_in)
	{
		this->logger->log(this->logger, CONTROL|MOST, "last responded message could not be set cause id was not as expected");
		return FAILED;
		
	}
	this->logger->log(this->logger, CONTROL|MOST, "replace last responded message with new one");
	this->last_responded_message = message;

	/* message counter can now be increased */
	this->logger->log(this->logger, CONTROL|MOST, "Increate message counter for incoming messages");
	this->message_id_in++;

	return SUCCESS;
}


/**
 * Implements protected_ike_sa_t.destroy.
 */
static void destroy (private_ike_sa_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy IKE_SA");

	/* destroy child sa's */
	this->logger->log(this->logger, CONTROL | MOST, "Destroy all child_sa's");
	while (this->child_sas->get_count(this->child_sas) > 0)
	{
		void *child_sa;
		if (this->child_sas->remove_first(this->child_sas, &child_sa) != SUCCESS)
		{
			break;
		}
		/* destroy child sa */
	}
	this->child_sas->destroy(this->child_sas);

	this->logger->log(this->logger, CONTROL | MOST, "Destroy secrets");
	
	allocator_free(this->secrets.d_key.ptr);
	allocator_free(this->secrets.ai_key.ptr);
	allocator_free(this->secrets.ar_key.ptr);
	allocator_free(this->secrets.ei_key.ptr);
	allocator_free(this->secrets.er_key.ptr);
	allocator_free(this->secrets.pi_key.ptr);
	allocator_free(this->secrets.pr_key.ptr);
	
	if (this->crypter_initiator != NULL)
	{
		this->crypter_initiator->destroy(this->crypter_initiator);
	}
	
	if (this->crypter_responder != NULL)
	{
		this->crypter_responder->destroy(this->crypter_responder);
	}
	
	if (this->signer_initiator != NULL)
	{
		this->signer_initiator->destroy(this->signer_initiator);
	}

	if (this->signer_responder != NULL)
	{
		this->signer_responder->destroy(this->signer_responder);
	}
	
	if (this->prf != NULL)
	{
		this->prf->destroy(this->prf);
	}
	
	/* destroy ike_sa_id */
	this->ike_sa_id->destroy(this->ike_sa_id);

	/* destroy stored requested message */
	if (this->last_requested_message != NULL)
	{
		this->last_requested_message->destroy(this->last_requested_message);
	}
	
	/* destroy stored responded messages */
	if (this->last_responded_message != NULL)
	{
		this->last_responded_message->destroy(this->last_responded_message);
	}
	
	this->randomizer->destroy(this->randomizer);

	if (this->me.host != NULL)
	{
		this->me.host->destroy(this->me.host);
	}
	
	if (this->other.host != NULL)
	{
		this->other.host->destroy(this->other.host);
	}
	
	this->logger->log(this->logger, CONTROL | MOST, "Destroy current state object");
	this->current_state->destroy(this->current_state);
	
	this->logger->log(this->logger, CONTROL | MOST, "Destroy logger of IKE_SA");
	global_logger_manager->destroy_logger(global_logger_manager, this->logger);

	allocator_free(this);
}

/*
 * Described in Header
 */
ike_sa_t * ike_sa_create(ike_sa_id_t *ike_sa_id)
{
	private_ike_sa_t *this = allocator_alloc_thing(private_ike_sa_t);

	/* Public functions */
	this->protected.public.process_message = (status_t(*)(ike_sa_t*, message_t*)) process_message;
	this->protected.public.initialize_connection = (status_t(*)(ike_sa_t*, char*)) initialize_connection;
	this->protected.public.get_id = (ike_sa_id_t*(*)(ike_sa_t*)) get_id;
	this->protected.public.destroy = (void(*)(ike_sa_t*))destroy;
	
	/* protected functions */
	this->protected.build_message = (void (*) (protected_ike_sa_t *, exchange_type_t , bool , message_t **)) build_message;
	this->protected.compute_secrets = (void (*) (protected_ike_sa_t *,chunk_t ,chunk_t , chunk_t )) compute_secrets;
	this->protected.get_logger = (logger_t *(*) (protected_ike_sa_t *)) get_logger;		
	this->protected.get_my_host = (host_t *(*) (protected_ike_sa_t *)) get_my_host;
	this->protected.get_other_host = (host_t *(*) (protected_ike_sa_t *)) get_other_host;
	this->protected.set_my_host = (void(*) (protected_ike_sa_t *,host_t *)) set_my_host;
	this->protected.set_other_host = (void(*) (protected_ike_sa_t *, host_t *)) set_other_host;
	this->protected.get_randomizer = (randomizer_t *(*) (protected_ike_sa_t *)) get_randomizer;
	this->protected.set_last_requested_message = (status_t (*) (protected_ike_sa_t *,message_t *)) set_last_requested_message;
	this->protected.set_last_responded_message = (status_t (*) (protected_ike_sa_t *,message_t *)) set_last_responded_message;
	this->protected.create_transforms_from_proposal = (status_t (*) (protected_ike_sa_t *,proposal_substructure_t *)) create_transforms_from_proposal;
	this->protected.set_new_state = (void (*) (protected_ike_sa_t *,state_t *)) set_new_state;

	/* private functions */
	this->resend_last_reply = resend_last_reply;
	this->create_delete_job = create_delete_job;


	/* initialize private fields */
	this->logger = global_logger_manager->create_logger(global_logger_manager, IKE_SA, NULL);
	
	this->ike_sa_id = ike_sa_id->clone(ike_sa_id);
	this->child_sas = linked_list_create();
	this->randomizer = randomizer_create();
	
	this->me.host = NULL;
	this->other.host = NULL;
	this->last_requested_message = NULL;
	this->last_responded_message = NULL;
	this->message_id_out = 0;
	this->message_id_in = 0;
	this->secrets.d_key = CHUNK_INITIALIZER;
	this->secrets.ai_key = CHUNK_INITIALIZER;
	this->secrets.ar_key = CHUNK_INITIALIZER;
	this->secrets.ei_key = CHUNK_INITIALIZER;	
	this->secrets.er_key = CHUNK_INITIALIZER;
	this->secrets.pi_key = CHUNK_INITIALIZER;
	this->secrets.pr_key = CHUNK_INITIALIZER;
	this->crypter_initiator = NULL;
	this->crypter_responder = NULL;
	this->signer_initiator = NULL;
	this->signer_responder = NULL;
	this->prf = NULL;
	
	/* at creation time, IKE_SA is in a initiator state */
	if (ike_sa_id->is_initiator(ike_sa_id))
	{
		this->current_state = (state_t *) initiator_init_create(&(this->protected));
	}
	else
	{
		this->current_state = (state_t *) responder_init_create(&(this->protected));
	}
	return &(this->protected.public);
}
