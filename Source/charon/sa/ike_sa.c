/**
 * @file ike_sa.c
 *
 * @brief Implementation of ike_sa_t.
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
#include <daemon.h>
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
#include <queues/jobs/retransmit_request_job.h>
#include <queues/jobs/delete_established_ike_sa_job.h>




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
	 * Resends the last sent reply.
	 * 
	 * @param this 				calling object
	 */
	status_t (*resend_last_reply) (private_ike_sa_t *this);

	/* private values */
	
	/**
	 * Identifier for the current IKE_SA.
	 */
	ike_sa_id_t *ike_sa_id;

	/**
	 * Linked List containing the child sa's of the current IKE_SA.
	 */
	linked_list_t *child_sas;
	
	/**
	 * Current state of the IKE_SA represented as state_t object.
	 * 
	 * A state object representates one of the following states and is processing 
	 * messages in the specific state:
	 *  - INITIATOR_INIT
	 *  - RESPONDER_INIT
	 *  - IKE_SA_INIT_REQUESTED
	 *  - IKE_SA_INIT_RESPONDED
	 *  - IKE_AUTH_REQUESTED
	 *   -IKE_SA_ESTABLISHED
	 */
	state_t *current_state;
	
	/**
	 * INIT configuration, needed for the IKE_SA_INIT exchange.
	 * 
	 * Gets set in states:
	 *  - INITATOR_INIT
	 *  - RESPONDER_INIT
	 * 
	 * Available in states:
	 *  - IKE_SA_INIT_REQUESTED
	 *  - IKE_SA_INIT_RESPONDED
	 *  - IKE_AUTH_REQUESTED
	 *   -IKE_SA_ESTABLISHED
	 */
	init_config_t *init_config;
	
	/**
	 * SA configuration, needed for all other exchanges after IKE_SA_INIT exchange.
	 * 
	 * Gets set in states:
	 *  - IKE_SA_INIT_REQUESTED
	 *  - IKE_SA_INIT_RESPONDED
	 * 
	 * Available in states:
	 *  - IKE_AUTH_REQUESTED
	 *   -IKE_SA_ESTABLISHED
	 */
	sa_config_t *sa_config;
	
	/**
	 * This SA's source for random data.
	 * 
	 * Is available in every state.
	 */
	randomizer_t *randomizer;
	
	/**
	 * The last responded message.
	 */
	message_t *last_responded_message;

	/**
	 * The ast requested message.
	 */
	message_t *last_requested_message;
	
	/**
	 * Informations of this host.
	 */
	struct {
		host_t *host;
	} me;

	/**
	 * Informations of the other host.
	 */	
	struct {
		host_t *host;
	} other;
	
	/**
	 * Crypter object for initiator.
	 * 
	 * Gets set in states:
	 *  - IKE_SA_INIT_REQUESTED
	 *  - RESPONDER_INIT
	 * 
	 * Available in states:
	 *  - IKE_SA_INIT_RESPONDED
	 *  - IKE_AUTH_REQUESTED
	 *   -IKE_SA_ESTABLISHED
	 */
	crypter_t *crypter_initiator;
	
	/**
	 * Crypter object for responder.
	 * 
	 * Gets set in states:
	 *  - IKE_SA_INIT_REQUESTED
	 *  - RESPONDER_INIT
	 * 
	 * Available in states:
	 *  - IKE_SA_INIT_RESPONDED
	 *  - IKE_AUTH_REQUESTED
	 *   -IKE_SA_ESTABLISHED
	 */
	crypter_t *crypter_responder;
	
	/**
	 * Signer object for initiator.
	 * 
	 * Gets set in states:
	 *  - IKE_SA_INIT_REQUESTED
	 *  - RESPONDER_INIT
	 * 
	 * Available in states:
	 *  - IKE_SA_INIT_RESPONDED
	 *  - IKE_AUTH_REQUESTED
	 *   -IKE_SA_ESTABLISHED
	 */
	signer_t *signer_initiator;
	
	/**
	 * Signer object for responder.
	 * 
	 * Gets set in states:
	 *  - IKE_SA_INIT_REQUESTED
	 *  - RESPONDER_INIT
	 * 
	 * Available in states:
	 *  - IKE_SA_INIT_RESPONDED
	 *  - IKE_AUTH_REQUESTED
	 *   -IKE_SA_ESTABLISHED
	 */
	signer_t *signer_responder;
	
	/**
	 * Prf function.
	 * 
	 * Gets set in states:
	 *  - IKE_SA_INIT_REQUESTED
	 *  - RESPONDER_INIT
	 * 
	 * Available in states:
	 *  - IKE_SA_INIT_RESPONDED
	 *  - IKE_AUTH_REQUESTED
	 *   -IKE_SA_ESTABLISHED
	 */
	prf_t *prf;
	
	/**
	 * Shared secrets which have to be stored.
	 * 
	 * Are getting set in states:
	 *  - IKE_SA_INIT_REQUESTED
	 *  - RESPONDER_INIT
	 * 
	 * Available in states:
	 *  - IKE_SA_INIT_RESPONDED
	 *  - IKE_AUTH_REQUESTED
	 *   -IKE_SA_ESTABLISHED
	 */
	struct {
		/**
		 * Key used for deriving other keys
		 */
		chunk_t d_key;

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
	 * Next message id to receive.
	 */
	u_int32_t message_id_in;
	
	/**
	 * Next message id to send.
	 */
	u_int32_t message_id_out;
	
	/**
	 * Last reply id which was successfully received.
	 */
	int32_t last_replied_message_id;
	
	/**
	 * A logger for this IKE_SA.
	 */
	logger_t *logger;
};

/**
 * Implementation of ike_sa_t.process_message.
 */
static status_t process_message (private_ike_sa_t *this, message_t *message)
{
	u_int32_t message_id;
	exchange_type_t exchange_type;
	bool is_request;
	
	/* We must process each request or response from remote host */

	/* Find out type of message (request or response) */
	is_request = message->get_request(message);
	exchange_type = message->get_exchange_type(message);

	this->logger->log(this->logger, CONTROL, "Process %s message of exchange type %s",(is_request) ? "REQUEST" : "RESPONSE",mapping_find(exchange_type_m,exchange_type));

	message_id = message->get_message_id(message);

	/* 
	 * It has to be checked, if the message has to be resent cause of lost packets!
	 */
	if (is_request && (message_id == (this->message_id_in - 1)))
	{
		/* Message can be resent ! */
		this->logger->log(this->logger, CONTROL|LEVEL1, "Resent request detected. Send stored reply.");
		return (this->resend_last_reply(this));
	}
	
	/* Now, the message id is checked for request AND reply */
	if (is_request)
	{
		/* In a request, the message has to be this->message_id_in (other case is already handled) */
		if (message_id != this->message_id_in)
		{
			this->logger->log(this->logger, ERROR | LEVEL1, "Message request with message id %d received, but %d expected",message_id,this->message_id_in);
			return FAILED;
		}
	}
	else
	{
		/* In a reply, the message has to be this->message_id_out -1 cause it is the reply to the last sent message*/
		if (message_id != (this->message_id_out - 1))
		{
			this->logger->log(this->logger, ERROR | LEVEL1, "Message reply with message id %d received, but %d expected",message_id,this->message_id_in);
			return FAILED;
		}
	}
	
	/* now the message is processed by the current state object.
	 * The specific state object is responsible to check if a message can be received in 
	 * the state it represents.
	 * The current state is also responsible to change the state object to the next state 
	 * by calling protected_ike_sa_t.set_new_state*/
	return this->current_state->process_message(this->current_state,message);
}

/**
 * Implementation of protected_ike_sa_t.build_message.
 */
static void build_message(private_ike_sa_t *this, exchange_type_t type, bool request, message_t **message)
{
	message_t *new_message; 

	this->logger->log(this->logger, CONTROL|LEVEL2, "Build empty message");
	new_message = message_create();	
	new_message->set_source(new_message, this->me.host->clone(this->me.host));
	new_message->set_destination(new_message, this->other.host->clone(this->other.host));
	new_message->set_exchange_type(new_message, type);
	new_message->set_request(new_message, request);
	new_message->set_message_id(new_message, (request) ? this->message_id_out : this->message_id_in);
	new_message->set_ike_sa_id(new_message, this->ike_sa_id);

	*message = new_message;
}

/**
 * Implementation of protected_ike_sa_t.process_configuration.
 */
static status_t initialize_connection(private_ike_sa_t *this, char *name)
{
	initiator_init_t *current_state;
	status_t status;

	/* Work is done in state object of type INITIATOR_INIT. All other states are not 
	 * initial states and so don't have a initialize_connection function */
	
	if (this->current_state->get_state(this->current_state) != INITIATOR_INIT)
	{
		return FAILED;
	}
	
	current_state = (initiator_init_t *) this->current_state;
	
	status = current_state->initiate_connection(current_state,name);
	return status;
}

/**
 * Implementation of protected_ike_sa_t.get_id.
 */
static ike_sa_id_t* get_id(private_ike_sa_t *this)
{
	return this->ike_sa_id;
}

/**
 * Implementation of protected_ike_sa_t.compute_secrets.
 */
static void compute_secrets(private_ike_sa_t *this,chunk_t dh_shared_secret,chunk_t initiator_nonce, chunk_t responder_nonce)
{
	u_int8_t ei_buffer[this->crypter_initiator->get_block_size(this->crypter_initiator)];
	chunk_t ei_key = {ptr: ei_buffer, len: sizeof(ei_buffer)};
	u_int8_t er_buffer[this->crypter_responder->get_block_size(this->crypter_responder)];
	chunk_t er_key = {ptr: er_buffer, len: sizeof(er_buffer)};
	u_int8_t ai_buffer[this->signer_initiator->get_key_size(this->signer_initiator)];
	chunk_t ai_key = {ptr: ai_buffer, len: sizeof(ai_buffer)};
	u_int8_t ar_buffer[this->signer_responder->get_key_size(this->signer_responder)];
	chunk_t ar_key = {ptr: ar_buffer, len: sizeof(ar_buffer)};
	u_int8_t concatenated_nonces_buffer[initiator_nonce.len + responder_nonce.len];
	chunk_t concatenated_nonces = {ptr: concatenated_nonces_buffer, len : sizeof(concatenated_nonces_buffer)};
	u_int8_t skeyseed_buffer[this->prf->get_block_size(this->prf)];
	chunk_t skeyseed = {ptr: skeyseed_buffer, len: sizeof(skeyseed_buffer)};
	u_int64_t initiator_spi;
	u_int64_t responder_spi;
	chunk_t prf_plus_seed;
	prf_plus_t *prf_plus;

	/* first is initiator */
	memcpy(concatenated_nonces.ptr,initiator_nonce.ptr,initiator_nonce.len);
	/* second is responder */
	memcpy(concatenated_nonces.ptr + initiator_nonce.len,responder_nonce.ptr,responder_nonce.len);

	this->logger->log_chunk(this->logger, RAW | LEVEL2, "Nonce data", &concatenated_nonces);

	/* Status of set_key is not checked */
	this->prf->set_key(this->prf,concatenated_nonces);

	this->prf->get_bytes(this->prf,dh_shared_secret,skeyseed_buffer);

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
	
	this->logger->log_chunk(this->logger, PRIVATE | LEVEL1, "Keyseed", &skeyseed);
	this->logger->log_chunk(this->logger, PRIVATE | LEVEL1, "PRF+ Seed", &prf_plus_seed);

	this->logger->log(this->logger, CONTROL | LEVEL2, "Set new key of prf object");
	this->prf->set_key(this->prf,skeyseed);
 
	this->logger->log(this->logger, CONTROL | LEVEL2, "Create new prf+ object");
	prf_plus = prf_plus_create(this->prf, prf_plus_seed);
	allocator_free_chunk(&prf_plus_seed);
	
	
	prf_plus->allocate_bytes(prf_plus,this->prf->get_block_size(this->prf),&(this->secrets.d_key));
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_d secret", &(this->secrets.d_key));

	prf_plus->get_bytes(prf_plus,ai_key.len,ai_buffer);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_ai secret", &(ai_key));
	this->signer_initiator->set_key(this->signer_initiator,ai_key);

	prf_plus->get_bytes(prf_plus,ar_key.len,ar_buffer);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_ar secret", &(ar_key));
	this->signer_responder->set_key(this->signer_responder,ar_key);

	prf_plus->get_bytes(prf_plus,ei_key.len,ei_buffer);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_ei secret", &(ei_key));
	this->crypter_initiator->set_key(this->crypter_initiator,ei_key);
	
	prf_plus->get_bytes(prf_plus,er_key.len,er_buffer);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_er secret", &(er_key));
	this->crypter_responder->set_key(this->crypter_responder,er_key);

	prf_plus->allocate_bytes(prf_plus,this->crypter_responder->get_block_size(this->crypter_responder),&(this->secrets.pi_key));
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_pi secret", &(this->secrets.pi_key));
	
	prf_plus->allocate_bytes(prf_plus,this->crypter_responder->get_block_size(this->crypter_responder),&(this->secrets.pr_key));
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_pr secret", &(this->secrets.pr_key));
	
	prf_plus->destroy(prf_plus);
}

/**
 * Implementation of private_ike_sa_t.resend_last_reply.
 */
static status_t resend_last_reply(private_ike_sa_t *this)
{
	packet_t *packet;
	
	this->logger->log(this->logger, CONTROL | LEVEL1, "Going to retransmit last reply");
	packet = this->last_responded_message->get_packet(this->last_responded_message);
	charon->send_queue->add(charon->send_queue, packet);

	return SUCCESS;
}

/**
 * Implementation of ike_sa_t.retransmit_request.
 */
status_t retransmit_request (private_ike_sa_t *this, u_int32_t message_id)
{
	packet_t *packet;
		
	if (this->last_requested_message == NULL)
	{
		return NOT_FOUND;
	}

	if (message_id == this->last_replied_message_id)
	{
		return NOT_FOUND;
	}

	if ((this->last_requested_message->get_message_id(this->last_requested_message)) != message_id)
	{
		return NOT_FOUND;
	}
	
	this->logger->log(this->logger, CONTROL | LEVEL1, "Going to retransmit message with id %d",message_id);
	packet = this->last_requested_message->get_packet(this->last_requested_message);
	charon->send_queue->add(charon->send_queue, packet);
	
	return SUCCESS;
}
	
/**
 * Implementation of protected_ike_sa_t.set_new_state.
 */
static void set_new_state (private_ike_sa_t *this, state_t *state)
{
	this->logger->log(this->logger, CONTROL, "Change current state %s to %s",
					  mapping_find(ike_sa_state_m,this->current_state->get_state(this->current_state)),
					  mapping_find(ike_sa_state_m,state->get_state(state)));
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
 * Implementation of protected_ike_sa_t.get_init_config.
 */
static init_config_t *get_init_config (private_ike_sa_t *this)
{
	return this->init_config;
}

/**
 * Implementation of protected_ike_sa_t.set_init_config.
 */
static void set_init_config (private_ike_sa_t *this,init_config_t * init_config)
{
	this->init_config = init_config;
}

/**
 * Implementation of protected_ike_sa_t.get_sa_config.
 */
static sa_config_t *get_sa_config (private_ike_sa_t *this)
{
	return this->sa_config;
}

/**
 * Implementation of protected_ike_sa_t.set_sa_config.
 */
static void set_sa_config (private_ike_sa_t *this,sa_config_t * sa_config)
{
	this->sa_config = sa_config;
}

/**
 * Implementation of protected_ike_sa_t.set_my_host.
 */
static void set_my_host (private_ike_sa_t *this, host_t *my_host)
{
	this->me.host = my_host;
}

/**
 * Implementation of protected_ike_sa_t.set_other_host.
 */
static void set_other_host (private_ike_sa_t *this, host_t *other_host)
{
	this->other.host = other_host;
}

/**
 * Implementation of protected_ike_sa_t.get_prf.
 */
static prf_t *get_prf (private_ike_sa_t *this)
{
	return this->prf;
}

/**
 * Implementation of protected_ike_sa_t.get_key_pr.
 */
static chunk_t get_key_pr (private_ike_sa_t *this)
{
	return this->secrets.pr_key;
}


/**
 * Implementation of protected_ike_sa_t.get_key_pi.
 */
static chunk_t get_key_pi (private_ike_sa_t *this)
{
	return this->secrets.pi_key;
}

/**
 * Implementation of protected_ike_sa_t.set_prf.
 */
static status_t create_transforms_from_proposal (private_ike_sa_t *this,ike_proposal_t *proposal)
{
	this->logger->log(this->logger, CONTROL|LEVEL1, "Going to create transform objects for proposal");
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "Encryption algorithm: %s with keylength %d",mapping_find(encryption_algorithm_m,proposal->encryption_algorithm),proposal->encryption_algorithm_key_length);
	this->logger->log(this->logger, CONTROL|LEVEL1, "integrity algorithm: %s with keylength %d",mapping_find(integrity_algorithm_m,proposal->integrity_algorithm),proposal->integrity_algorithm_key_length);
	this->logger->log(this->logger, CONTROL|LEVEL1, "prf: %s with keylength %d",mapping_find(pseudo_random_function_m,proposal->pseudo_random_function),proposal->pseudo_random_function_key_length);
	
	if (this->prf != NULL)
	{
		this->prf->destroy(this->prf);
	}
	this->prf = prf_create(proposal->pseudo_random_function);
	if (this->prf == NULL)
	{
		this->logger->log(this->logger, ERROR|LEVEL1, "prf not supported!");
		return FAILED;
	}
	
	if (this->crypter_initiator != NULL)
	{
		this->crypter_initiator->destroy(this->crypter_initiator);
	}
	this->crypter_initiator = crypter_create(proposal->encryption_algorithm,proposal->encryption_algorithm_key_length);
	if (this->crypter_initiator == NULL)
	{
		this->logger->log(this->logger, ERROR|LEVEL1, "encryption algorithm %s not supported!",
						  mapping_find(encryption_algorithm_m,proposal->encryption_algorithm));
		return FAILED;
	}

	if (this->crypter_responder != NULL)
	{
		this->crypter_responder->destroy(this->crypter_responder);
	}
	this->crypter_responder = crypter_create(proposal->encryption_algorithm,proposal->encryption_algorithm_key_length);
	/* check must not be done again */
	
	if (this->signer_initiator != NULL)
	{
		this->signer_initiator->destroy(this->signer_initiator);
	}
	this->signer_initiator = signer_create(proposal->integrity_algorithm);
	if (this->signer_initiator == NULL)
	{
		this->logger->log(this->logger, ERROR|LEVEL1, "integrity algorithm not supported!");
		return FAILED;
	}
	
	if (this->signer_responder != NULL)
	{
		this->signer_responder->destroy(this->signer_responder);
	}
	this->signer_responder = signer_create(proposal->integrity_algorithm);

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
 * Implementation of protected_ike_sa_t.get_crypter_initiator.
 */
static crypter_t *get_crypter_initiator (private_ike_sa_t *this)
{
	return this->crypter_initiator;
}

/**
 * Implementation of protected_ike_sa_t.get_signer_initiator.
 */
static signer_t *get_signer_initiator (private_ike_sa_t *this)
{
	return this->signer_initiator;
}

/**
 * Implementation of protected_ike_sa_t.get_crypter_responder.
 */
static crypter_t *get_crypter_responder(private_ike_sa_t *this)
{
	return this->crypter_responder;
}

/**
 * Implementation of protected_ike_sa_t.get_signer_responder.
 */
static signer_t *get_signer_responder (private_ike_sa_t *this)
{
	return this->signer_responder;
}

/**
 * Implementation of protected_ike_sa_t.send_request.
 */
static status_t send_request (private_ike_sa_t *this,message_t * message)
{
	retransmit_request_job_t *retransmit_job;
	u_int32_t timeout;
	packet_t *packet;
	status_t status;
	
	if (message->get_message_id(message) != this->message_id_out)
	{
		this->logger->log(this->logger, ERROR, "Message could not be sent cause id (%d) was not as expected (%d)",
							message->get_message_id(message),this->message_id_out);
		return FAILED;
	}

	/* generate packet */	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Generate packet from message");

	status = message->generate(message, this->crypter_initiator,this->signer_initiator, &packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not generate packet from message");
		return FAILED;
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Add packet to global send queue");
	charon->send_queue->add(charon->send_queue, packet);
	
	if (this->last_requested_message != NULL)
	{
		/* destroy message */
		this->last_requested_message->destroy(this->last_requested_message);
	}	

	this->logger->log(this->logger, CONTROL|LEVEL2, "replace last requested message with new one");
	this->last_requested_message = message;
	
	retransmit_job = retransmit_request_job_create(this->message_id_out,this->ike_sa_id);
	
	status = charon->configuration_manager->get_retransmit_timeout (charon->configuration_manager,retransmit_job->get_retransmit_count(retransmit_job),&timeout);
	
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, CONTROL|LEVEL2, "No retransmit job for message created!");
		retransmit_job->destroy(retransmit_job);
	}
	else
	{
		this->logger->log(this->logger, CONTROL|LEVEL2, "Request will be retransmitted in %d ms.",timeout);
		charon->event_queue->add_relative(charon->event_queue,(job_t *) retransmit_job,timeout);
	}
	
	/* message counter can now be increased */
	this->logger->log(this->logger, CONTROL|LEVEL2, "Increase message counter for outgoing messages from %d",this->message_id_out);
	this->message_id_out++;
	return SUCCESS;	
}

/**
 * Implementation of protected_ike_sa_t.send_response.
 */
static status_t send_response (private_ike_sa_t *this,message_t * message)
{
	packet_t *packet;
	status_t status;
	
	if (message->get_message_id(message) != this->message_id_in)
	{
		this->logger->log(this->logger, CONTROL|LEVEL2, "Message could not be sent cause id was not as expected");
		return FAILED;	
	}
	
	status = message->generate(message, this->crypter_responder,this->signer_responder, &packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not generate packet from message");
		return FAILED;
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Add packet to global send queue");
	charon->send_queue->add(charon->send_queue, packet);
	
	if (this->last_responded_message != NULL)
	{
		/* destroy message */
		this->last_responded_message->destroy(this->last_responded_message);
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "replace last responded message with new one");
	this->last_responded_message = message;

	/* message counter can now be increased */
	this->logger->log(this->logger, CONTROL|LEVEL2, "Increase message counter for incoming messages");
	this->message_id_in++;

	return SUCCESS;
}

/**
 * Implementation of protected_ike_sa_t.set_last_replied_message_id.
 */
static void set_last_replied_message_id (private_ike_sa_t *this,u_int32_t message_id)
{
	this->last_replied_message_id = message_id;
}

/**
 * Implementation of protected_ike_sa_t.get_last_responded_message.
 */
static message_t * get_last_responded_message (private_ike_sa_t *this)
{
	return this->last_responded_message;
}

/**
 * Implementation of protected_ike_sa_t.get_last_requested_message.
 */
static message_t * get_last_requested_message (private_ike_sa_t *this)
{
	return this->last_requested_message;
}

static ike_sa_state_t get_state (private_ike_sa_t *this)
{
	return this->current_state->get_state(this->current_state);
}

/**
 * Implementation of protected_ike_sa_t.reset_message_buffers.
 */
static void reset_message_buffers (private_ike_sa_t *this)
{
	this->logger->log(this->logger, CONTROL|LEVEL2, "Reset message counters and destroy stored messages");
	/* destroy stored requested message */
	if (this->last_requested_message != NULL)
	{
		this->last_requested_message->destroy(this->last_requested_message);
		this->last_requested_message = NULL;
	}
	
	/* destroy stored responded messages */
	if (this->last_responded_message != NULL)
	{
		this->last_responded_message->destroy(this->last_responded_message);
		this->last_responded_message = NULL;
	}
	
	this->message_id_out = 0;
	this->message_id_in = 0;
	this->last_replied_message_id = -1;
}

static void create_delete_established_ike_sa_job (private_ike_sa_t *this,u_int32_t timeout)
{
	job_t *delete_job;

	this->logger->log(this->logger, CONTROL | LEVEL1, "Going to create job to delete established IKE_SA in %d ms", timeout);

	delete_job = (job_t *) delete_established_ike_sa_job_create(this->ike_sa_id);
	charon->event_queue->add_relative(charon->event_queue,delete_job, timeout);
}

/**
 * Implementation of protected_ike_sa_t.destroy.
 */
static void destroy (private_ike_sa_t *this)
{
	this->logger->log(this->logger, CONTROL|LEVEL2, "Going to destroy IKE SA %llu:%llu, role %s", 
					  this->ike_sa_id->get_initiator_spi(this->ike_sa_id),
					  this->ike_sa_id->get_responder_spi(this->ike_sa_id),
					  this->ike_sa_id->is_initiator(this->ike_sa_id) ? "initiator" : "responder");

	/* destroy child sa's */
	this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy all child_sa's");
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

	this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy secrets");
	allocator_free(this->secrets.d_key.ptr);
	allocator_free(this->secrets.pi_key.ptr);
	allocator_free(this->secrets.pr_key.ptr);
	
	if (this->crypter_initiator != NULL)
	{
		this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy initiator crypter_t object");
		this->crypter_initiator->destroy(this->crypter_initiator);
	}
	
	if (this->crypter_responder != NULL)
	{
		this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy responder crypter_t object");
		this->crypter_responder->destroy(this->crypter_responder);
	}
	
	if (this->signer_initiator != NULL)
	{
		this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy initiator signer_t object");
		this->signer_initiator->destroy(this->signer_initiator);
	}

	if (this->signer_responder != NULL)
	{
		this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy responder signer_t object");
		this->signer_responder->destroy(this->signer_responder);
	}
	
	if (this->prf != NULL)
	{
		this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy prf_t object");
		this->prf->destroy(this->prf);
	}
	
	/* destroy ike_sa_id */
	this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy ike_sa_id object");
	this->ike_sa_id->destroy(this->ike_sa_id);

	/* destroy stored requested message */
	if (this->last_requested_message != NULL)
	{
		this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy last requested message");
		this->last_requested_message->destroy(this->last_requested_message);
	}
	
	/* destroy stored responded messages */
	if (this->last_responded_message != NULL)
	{
		this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy last responded message");
		this->last_responded_message->destroy(this->last_responded_message);
	}
	
	/* destroy stored host_t objects */
	if (this->me.host != NULL)
	{
		this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy my host_t object");
		this->me.host->destroy(this->me.host);
	}
	
	/* destroy stored host_t objects */
	if (this->other.host != NULL)
	{
		this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy other host_t object");
		this->other.host->destroy(this->other.host);
	}
		
	this->randomizer->destroy(this->randomizer);

	this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy current state object");
	this->current_state->destroy(this->current_state);
	
	this->logger->log(this->logger, CONTROL | LEVEL2, "Destroy logger of IKE_SA");
	charon->logger_manager->destroy_logger(charon->logger_manager, this->logger);

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
	this->protected.public.retransmit_request = (status_t (*) (ike_sa_t *, u_int32_t)) retransmit_request;
	this->protected.public.get_state = (ike_sa_state_t (*) (ike_sa_t *this)) get_state;
	this->protected.public.destroy = (void(*)(ike_sa_t*))destroy;
	
	/* protected functions */
	this->protected.build_message = (void (*) (protected_ike_sa_t *, exchange_type_t , bool , message_t **)) build_message;
	this->protected.compute_secrets = (void (*) (protected_ike_sa_t *,chunk_t ,chunk_t , chunk_t )) compute_secrets;
	this->protected.get_prf = (prf_t *(*) (protected_ike_sa_t *)) get_prf;	
	this->protected.get_key_pr = (chunk_t (*) (protected_ike_sa_t *)) get_key_pr;	
	this->protected.get_key_pi = (chunk_t (*) (protected_ike_sa_t *)) get_key_pi;	
	this->protected.get_logger = (logger_t *(*) (protected_ike_sa_t *)) get_logger;		
	this->protected.set_init_config = (void (*) (protected_ike_sa_t *,init_config_t *)) set_init_config;
	this->protected.get_init_config = (init_config_t *(*) (protected_ike_sa_t *)) get_init_config;
	this->protected.set_sa_config = (void (*) (protected_ike_sa_t *,sa_config_t *)) set_sa_config;
	this->protected.get_sa_config = (sa_config_t *(*) (protected_ike_sa_t *)) get_sa_config;
	this->protected.get_my_host = (host_t *(*) (protected_ike_sa_t *)) get_my_host;
	this->protected.get_other_host = (host_t *(*) (protected_ike_sa_t *)) get_other_host;
	this->protected.set_my_host = (void(*) (protected_ike_sa_t *,host_t *)) set_my_host;
	this->protected.set_other_host = (void(*) (protected_ike_sa_t *, host_t *)) set_other_host;
	this->protected.get_randomizer = (randomizer_t *(*) (protected_ike_sa_t *)) get_randomizer;
	this->protected.send_request = (status_t (*) (protected_ike_sa_t *,message_t *)) send_request;
	this->protected.send_response = (status_t (*) (protected_ike_sa_t *,message_t *)) send_response;
	this->protected.create_transforms_from_proposal = (status_t (*) (protected_ike_sa_t *,ike_proposal_t *)) create_transforms_from_proposal;
	this->protected.set_new_state = (void (*) (protected_ike_sa_t *,state_t *)) set_new_state;
	this->protected.get_crypter_initiator = (crypter_t *(*) (protected_ike_sa_t *)) get_crypter_initiator;
	this->protected.get_signer_initiator = (signer_t *(*) (protected_ike_sa_t *)) get_signer_initiator;	
	this->protected.get_crypter_responder = (crypter_t *(*) (protected_ike_sa_t *)) get_crypter_responder;
	this->protected.get_signer_responder = (signer_t *(*) (protected_ike_sa_t *)) get_signer_responder;	
	this->protected.reset_message_buffers = (void (*) (protected_ike_sa_t *)) reset_message_buffers;
	this->protected.get_last_responded_message = (message_t * (*) (protected_ike_sa_t *this)) get_last_responded_message;
	this->protected.get_last_requested_message = (message_t * (*) (protected_ike_sa_t *this)) get_last_requested_message;
	this->protected.create_delete_established_ike_sa_job = (void (*) (protected_ike_sa_t *this,u_int32_t)) create_delete_established_ike_sa_job;
	
	this->protected.set_last_replied_message_id = (void (*) (protected_ike_sa_t *,u_int32_t)) set_last_replied_message_id;
	
	/* private functions */
	this->resend_last_reply = resend_last_reply;

	/* initialize private fields */
	this->logger = charon->logger_manager->create_logger(charon->logger_manager, IKE_SA, NULL);
	
	this->ike_sa_id = ike_sa_id->clone(ike_sa_id);
	this->child_sas = linked_list_create();
	this->randomizer = randomizer_create();
	
	this->me.host = NULL;
	this->other.host = NULL;
	this->last_requested_message = NULL;
	this->last_responded_message = NULL;
	this->message_id_out = 0;
	this->message_id_in = 0;
	this->last_replied_message_id = -1;
	this->secrets.d_key = CHUNK_INITIALIZER;
	this->secrets.pi_key = CHUNK_INITIALIZER;
	this->secrets.pr_key = CHUNK_INITIALIZER;
	this->crypter_initiator = NULL;
	this->crypter_responder = NULL;
	this->signer_initiator = NULL;
	this->signer_responder = NULL;
	this->prf = NULL;
	this->init_config = NULL;
	this->sa_config = NULL;
	
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
