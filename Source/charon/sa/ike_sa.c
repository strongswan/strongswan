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
#include <encoding/payloads/delete_payload.h>
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
	connection_t *connection;
	
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
	policy_t *policy;
	
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
	 * Crypter object for initiator.
	 */
	crypter_t *crypter_initiator;
	
	/**
	 * Crypter object for responder.
	 */
	crypter_t *crypter_responder;
	
	/**
	 * Signer object for initiator.
	 */
	signer_t *signer_initiator;
	
	/**
	 * Signer object for responder.
	 */
	signer_t *signer_responder;
	
	/**
	 * Multi purpose prf, set key, use it, forget it
	 */
	prf_t *prf;
	
	/**
	 * Prf function for derivating keymat child SAs
	 */
	prf_t *child_prf;
	
	/**
	 * PRF, with key set to pi_key, used for authentication
	 */
	prf_t *prf_auth_i;

	/**
	 * PRF, with key set to pr_key, used for authentication
	 */
	prf_t *prf_auth_r;

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

	/**
	 * Resends the last sent reply.
	 * 
	 * @param this 				calling object
	 */
	status_t (*resend_last_reply) (private_ike_sa_t *this);
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

	this->logger->log(this->logger, CONTROL|LEVEL1, "Process %s of exchange type %s",
					  (is_request) ? "request" : "response",mapping_find(exchange_type_m,exchange_type));

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
			this->logger->log(this->logger, ERROR | LEVEL1,
								"Message request with message id %d received, but %d expected",
								message_id,this->message_id_in);
			return FAILED;
		}
	}
	else
	{
		/* In a reply, the message has to be this->message_id_out -1 cause it is the reply to the last sent message*/
		if (message_id != (this->message_id_out - 1))
		{
			this->logger->log(this->logger, ERROR | LEVEL1,
								"Message reply with message id %d received, but %d expected",
								message_id,this->message_id_in);
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
	host_t *me, *other;
	
	me = this->connection->get_my_host(this->connection);
	other = this->connection->get_other_host(this->connection);

	this->logger->log(this->logger, CONTROL|LEVEL2, "Build empty message");
	new_message = message_create();	
	new_message->set_source(new_message, me->clone(me));
	new_message->set_destination(new_message, other->clone(other));
	new_message->set_exchange_type(new_message, type);
	new_message->set_request(new_message, request);
	new_message->set_message_id(new_message, (request) ? this->message_id_out : this->message_id_in);
	new_message->set_ike_sa_id(new_message, this->ike_sa_id);

	*message = new_message;
}

/**
 * Implementation of protected_ike_sa_t.initiate_connection.
 */
static status_t initiate_connection(private_ike_sa_t *this, connection_t *connection)
{
	initiator_init_t *current_state;

	/* Work is done in state object of type INITIATOR_INIT. All other states are not 
	 * initial states and so don't have a initialize_connection function */
	
	if (this->current_state->get_state(this->current_state) != INITIATOR_INIT)
	{
		return FAILED;
	}
	
	current_state = (initiator_init_t *) this->current_state;
	
	return current_state->initiate_connection(current_state, connection);
}

/**
 * Implementation of ike_sa_t.send_delete_ike_sa_request.
 */
static void send_delete_ike_sa_request (private_ike_sa_t *this)
{
	message_t *informational_request;
	delete_payload_t *delete_payload;
	crypter_t *crypter;
	signer_t *signer;
	packet_t *packet;
	status_t status;
	
	if (this->current_state->get_state(this->current_state) != IKE_SA_ESTABLISHED)
	{
		return;
	}
	
	/* build empty INFORMATIONAL message */
	this->protected.build_message(&(this->protected), INFORMATIONAL, TRUE, &informational_request);
	
	delete_payload = delete_payload_create();
	delete_payload->set_protocol_id(delete_payload, PROTO_IKE);
		
	informational_request->add_payload(informational_request,(payload_t *)delete_payload);
	
	if (this->ike_sa_id->is_initiator(this->ike_sa_id))
	{
		crypter = this->crypter_initiator;
		signer = this->signer_initiator;
	}
	else
	{
		crypter = this->crypter_responder;
		signer = this->signer_responder;
	}
	
	status = informational_request->generate(informational_request,
											 crypter,
											 signer, &packet);
	informational_request->destroy(informational_request);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not generate packet from message");
		return ;
	}
	
	charon->send_queue->add(charon->send_queue,packet);
}

/**
 * Implementation of protected_ike_sa_t.get_id.
 */
static ike_sa_id_t* get_id(private_ike_sa_t *this)
{
	return this->ike_sa_id;
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
	this->logger->log(this->logger, CONTROL, "statechange: %s => %s",
					  mapping_find(ike_sa_state_m,this->current_state->get_state(this->current_state)),
					  mapping_find(ike_sa_state_m,state->get_state(state)));
	this->current_state = state;
}

/**
 * Implementation of protected_ike_sa_t.get_connection.
 */
static connection_t *get_connection (private_ike_sa_t *this)
{
	return this->connection;
}

/**
 * Implementation of protected_ike_sa_t.set_connection.
 */
static void set_connection (private_ike_sa_t *this,connection_t * connection)
{
	this->connection = connection;
}

/**
 * Implementation of protected_ike_sa_t.get_policy.
 */
static policy_t *get_policy (private_ike_sa_t *this)
{
	return this->policy;
}

/**
 * Implementation of protected_ike_sa_t.set_policy.
 */
static void set_policy (private_ike_sa_t *this,policy_t * policy)
{
	this->policy = policy;
}

/**
 * Implementation of protected_ike_sa_t.get_prf.
 */
static prf_t *get_prf (private_ike_sa_t *this)
{
	return this->prf;
}

/**
 * Implementation of protected_ike_sa_t.get_prf.
 */
static prf_t *get_child_prf (private_ike_sa_t *this)
{
	return this->child_prf;
}

/**
 * Implementation of protected_ike_sa_t.get_prf_auth_i.
 */
static prf_t *get_prf_auth_i (private_ike_sa_t *this)
{
	return this->prf_auth_i;
}

/**
 * Implementation of protected_ike_sa_t.get_prf_auth_r.
 */
static prf_t *get_prf_auth_r (private_ike_sa_t *this)
{
	return this->prf_auth_r;
}


/**
 * Implementation of protected_ike_sa_t.build_transforms.
 */
static status_t build_transforms(private_ike_sa_t *this, proposal_t *proposal, diffie_hellman_t *dh, chunk_t nonce_i, chunk_t nonce_r)
{
	chunk_t nonces, nonces_spis, skeyseed, key, secret;
	u_int64_t spi_i, spi_r;
	prf_plus_t *prf_plus;
	algorithm_t *algo;
	size_t key_size;
	
	/*
	 * Build the PRF+ instance for deriving keys
	 */
	if (this->prf != NULL)
	{
		this->prf->destroy(this->prf);
	}
	proposal->get_algorithm(proposal, PROTO_IKE, PSEUDO_RANDOM_FUNCTION, &algo);
	if (algo == NULL)
	{
		this->logger->log(this->logger, ERROR|LEVEL2, "No PRF algoithm selected!?");
		return FAILED;
	}
	this->prf = prf_create(algo->algorithm);
	if (this->prf == NULL)
	{
		this->logger->log(this->logger, ERROR|LEVEL1, 
						  "PSEUDO_RANDOM_FUNCTION %s not supported!",
						  mapping_find(pseudo_random_function_m, algo->algorithm));
		return FAILED;
	}
	
	/* concatenate nonces =  nonce_i | nonce_r */
	nonces = allocator_alloc_as_chunk(nonce_i.len + nonce_r.len);
	memcpy(nonces.ptr, nonce_i.ptr, nonce_i.len);
	memcpy(nonces.ptr + nonce_i.len, nonce_r.ptr, nonce_r.len);

	/* concatenate prf_seed = nonce_i | nonce_r | spi_i | spi_r */
	nonces_spis = allocator_alloc_as_chunk(nonces.len + 16);
	memcpy(nonces_spis.ptr, nonces.ptr, nonces.len);
	spi_i = this->ike_sa_id->get_initiator_spi(this->ike_sa_id);
	spi_r = this->ike_sa_id->get_responder_spi(this->ike_sa_id);
	memcpy(nonces_spis.ptr + nonces.len, &spi_i, 8);
	memcpy(nonces_spis.ptr + nonces.len + 8, &spi_r, 8);
	
	/* SKEYSEED = prf(Ni | Nr, g^ir) */
	dh->get_shared_secret(dh, &secret);
	this->logger->log_chunk(this->logger, PRIVATE, "Shared Diffie Hellman secret", secret);
	this->prf->set_key(this->prf, nonces);
	this->prf->allocate_bytes(this->prf, secret, &skeyseed);
	this->logger->log_chunk(this->logger, PRIVATE | LEVEL1, "SKEYSEED", skeyseed);
	allocator_free_chunk(&secret);

	/* prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )
	 * = SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr
	 *
	 * we use the prf directly for prf+ 
	 */
	this->prf->set_key(this->prf, skeyseed);
	prf_plus = prf_plus_create(this->prf, nonces_spis);
	
	/* clean up unused stuff */
	allocator_free_chunk(&nonces);
	allocator_free_chunk(&nonces_spis);
	allocator_free_chunk(&skeyseed);
	
	
	/*
	 * We now can derive all of our key. We build the transforms 
	 * directly.
	 */
	
	
	/* SK_d used for prf+ to derive keys for child SAs */
	this->child_prf = prf_create(algo->algorithm);
	key_size = this->child_prf->get_key_size(this->child_prf);
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_d secret", key);
	this->child_prf->set_key(this->child_prf, key);
	allocator_free_chunk(&key);
	
	
	/* SK_ai/SK_ar used for integrity protection */
	proposal->get_algorithm(proposal, PROTO_IKE, INTEGRITY_ALGORITHM, &algo);
	if (algo == NULL)
	{
		this->logger->log(this->logger, ERROR|LEVEL2, "No integrity algoithm selected?!");
		return FAILED;
	}
	if (this->signer_initiator != NULL)
	{
		this->signer_initiator->destroy(this->signer_initiator);
	}
	if (this->signer_responder != NULL)
	{
		this->signer_responder->destroy(this->signer_responder);
	}
	
	this->signer_initiator = signer_create(algo->algorithm);
	this->signer_responder = signer_create(algo->algorithm);
	if (this->signer_initiator == NULL || this->signer_responder == NULL)
	{
		this->logger->log(this->logger, ERROR|LEVEL1, 
						  "INTEGRITY_ALGORITHM %s not supported!",
						  mapping_find(integrity_algorithm_m,algo->algorithm));
		return FAILED;
	}
	key_size = this->signer_initiator->get_key_size(this->signer_initiator);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_ai secret", key);
	this->signer_initiator->set_key(this->signer_initiator, key);
	allocator_free_chunk(&key);

	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_ar secret", key);
	this->signer_responder->set_key(this->signer_responder, key);
	allocator_free_chunk(&key);
	
	
	/* SK_ei/SK_er used for encryption */
	proposal->get_algorithm(proposal, PROTO_IKE, ENCRYPTION_ALGORITHM, &algo);
	if (algo == NULL)
	{
		this->logger->log(this->logger, ERROR|LEVEL2, "No encryption algoithm selected!?");
		return FAILED;
	}
	if (this->crypter_initiator != NULL)
	{
		this->crypter_initiator->destroy(this->crypter_initiator);
	}
	if (this->crypter_responder != NULL)
	{
		this->crypter_responder->destroy(this->crypter_responder);
	}
	
	this->crypter_initiator = crypter_create(algo->algorithm, algo->key_size);
	this->crypter_responder = crypter_create(algo->algorithm, algo->key_size);
	if (this->crypter_initiator == NULL || this->crypter_responder == NULL)
	{
		this->logger->log(this->logger, ERROR|LEVEL1, 
						  "ENCRYPTION_ALGORITHM %s (key size %d) not supported!",
						  mapping_find(encryption_algorithm_m, algo->algorithm),
						  algo->key_size);
		return FAILED;
	}
	key_size = this->crypter_initiator->get_key_size(this->crypter_initiator);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_ei secret", key);
	this->crypter_initiator->set_key(this->crypter_initiator, key);
	allocator_free_chunk(&key);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_er secret", key);
	this->crypter_responder->set_key(this->crypter_responder, key);
	allocator_free_chunk(&key);
	
	/* SK_pi/SK_pr used for authentication */
	proposal->get_algorithm(proposal, PROTO_IKE, PSEUDO_RANDOM_FUNCTION, &algo);
	if (this->prf_auth_i != NULL)
	{
		this->prf_auth_i->destroy(this->prf_auth_i);
	}
	if (this->prf_auth_r != NULL)
	{
		this->prf_auth_r->destroy(this->prf_auth_r);
	}
	
	this->prf_auth_i = prf_create(algo->algorithm);
	this->prf_auth_r = prf_create(algo->algorithm);
	
	key_size = this->prf_auth_i->get_key_size(this->prf_auth_i);
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_pi secret", key);
	this->prf_auth_i->set_key(this->prf_auth_i, key);
	allocator_free_chunk(&key);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	this->logger->log_chunk(this->logger, PRIVATE, "Sk_pr secret", key);
	this->prf_auth_r->set_key(this->prf_auth_r, key);
	allocator_free_chunk(&key);
	
	/* all done, prf_plus not needed anymore */
	prf_plus->destroy(prf_plus);
	
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
	crypter_t *crypter;
	signer_t *signer;
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

	if (this->ike_sa_id->is_initiator(this->ike_sa_id))
	{
		crypter = this->crypter_initiator;
		signer = this->signer_initiator;
	}
	else
	{
		crypter = this->crypter_responder;
		signer =this->signer_responder;
	}
	
	status = message->generate(message, crypter,signer, &packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not generate packet from message");
		return FAILED;
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL3,
						"Add request packet with message id %d to global send queue",
						this->message_id_out);
	charon->send_queue->add(charon->send_queue, packet);
	
	if (this->last_requested_message != NULL)
	{
		/* destroy message */
		this->last_requested_message->destroy(this->last_requested_message);
	}	

	this->logger->log(this->logger, CONTROL|LEVEL3, "Replace last requested message with new one");
	this->last_requested_message = message;
	
	retransmit_job = retransmit_request_job_create(this->message_id_out,this->ike_sa_id);
	
	status = charon->configuration->get_retransmit_timeout (charon->configuration,
												retransmit_job->get_retransmit_count(retransmit_job),&timeout);
	
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
	this->logger->log(this->logger, CONTROL|LEVEL3,
						"Increase message counter for outgoing messages from %d",
						this->message_id_out);
	this->message_id_out++;
	return SUCCESS;	
}

/**
 * Implementation of protected_ike_sa_t.send_response.
 */
static status_t send_response (private_ike_sa_t *this,message_t * message)
{
	crypter_t *crypter;
	signer_t *signer;
	packet_t *packet;
	status_t status;
	
	if (message->get_message_id(message) != this->message_id_in)
	{
		this->logger->log(this->logger, ERROR, "Message could not be sent cause id was not as expected");
		return FAILED;	
	}
	

	if (this->ike_sa_id->is_initiator(this->ike_sa_id))
	{
		crypter = this->crypter_initiator;
		signer = this->signer_initiator;
	}
	else
	{
		crypter = this->crypter_responder;
		signer =this->signer_responder;
	}
	
	status = message->generate(message, crypter,signer, &packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not generate packet from message");
		return FAILED;
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL3,
						"Add response packet with message id %d to global send queue",
						this->message_id_in);
	charon->send_queue->add(charon->send_queue, packet);
	
	if (this->last_responded_message != NULL)
	{
		/* destroy message */
		this->last_responded_message->destroy(this->last_responded_message);
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL3, "Replace last responded message with new one");
	this->last_responded_message = message;

	/* message counter can now be increased */
	this->logger->log(this->logger, CONTROL|LEVEL3, "Increase message counter for incoming messages");
	this->message_id_in++;

	return SUCCESS;
}

/**
 * Implementation of of private_responder_init_t.send_notify_reply.
 */
static void send_notify(private_ike_sa_t *this, exchange_type_t exchange_type, notify_message_type_t type, chunk_t data)
{
	notify_payload_t *payload;
	message_t *response;
	packet_t *packet;
	status_t status;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Going to build message with notify payload");
	/* set up the reply */
	this->protected.build_message(&(this->protected), exchange_type, FALSE, &response);
	payload = notify_payload_create_from_protocol_and_type(PROTO_IKE, type);
	if ((data.ptr != NULL) && (data.len > 0))
	{
		this->logger->log(this->logger, CONTROL|LEVEL2, "Add Data to notify payload");
		payload->set_notification_data(payload,data);
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Add Notify payload to message");
	response->add_payload(response,(payload_t *) payload);
	
	/* generate packet */	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Generate packet from message");
	status = response->generate(response, this->crypter_responder, this->signer_responder, &packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR|LEVEL1, "Could not generate notify message");
		response->destroy(response);
		return;
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Add packet to global send queue");
	charon->send_queue->add(charon->send_queue, packet);
	this->logger->log(this->logger, CONTROL|LEVEL2, "Destroy message");
	response->destroy(response);
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

/**
 * Implementation of protected_ike_sa_t.get_state.
 */
static ike_sa_state_t get_state (private_ike_sa_t *this)
{
	return this->current_state->get_state(this->current_state);
}

/**
 * Implementation of protected_ike_sa_t.get_state.
 */
static void add_child_sa (private_ike_sa_t *this, child_sa_t *child_sa)
{
	this->child_sas->insert_last(this->child_sas, child_sa);
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

/**
 * Implementation of protected_ike_sa_t.destroy.
 */
static void destroy (private_ike_sa_t *this)
{
	child_sa_t *child_sa;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Going to destroy IKE SA %llu:%llu, role %s", 
					  this->ike_sa_id->get_initiator_spi(this->ike_sa_id),
					  this->ike_sa_id->get_responder_spi(this->ike_sa_id),
					  this->ike_sa_id->is_initiator(this->ike_sa_id) ? "initiator" : "responder");

	/* inform other peer of delete */
	send_delete_ike_sa_request(this);
	while (this->child_sas->remove_last(this->child_sas, (void**)&child_sa) == SUCCESS)
	{
		child_sa->destroy(child_sa);
	}
	this->child_sas->destroy(this->child_sas);
	
	if (this->crypter_initiator)
	{
		this->crypter_initiator->destroy(this->crypter_initiator);
	}
	if (this->crypter_responder)
	{
		this->crypter_responder->destroy(this->crypter_responder);
	}
	if (this->signer_initiator)
	{
		this->signer_initiator->destroy(this->signer_initiator);
	}
	if (this->signer_responder)
	{
		this->signer_responder->destroy(this->signer_responder);
	}
	if (this->prf)
	{
		this->prf->destroy(this->prf);
	}
	if (this->child_prf)
	{
		this->child_prf->destroy(this->child_prf);
	}
	if (this->prf_auth_i)
	{
		this->prf_auth_i->destroy(this->prf_auth_i);
	}
	if (this->prf_auth_r)
	{
		this->prf_auth_r->destroy(this->prf_auth_r);
	}
	if (this->connection)
	{
		this->connection->destroy(this->connection);
	}
	if (this->policy)
	{
		this->policy->destroy(this->policy);
	}
	if (this->last_requested_message)
	{
		this->last_requested_message->destroy(this->last_requested_message);
	}
	if (this->last_responded_message)
	{
		this->last_responded_message->destroy(this->last_responded_message);
	}
	this->ike_sa_id->destroy(this->ike_sa_id);
	this->randomizer->destroy(this->randomizer);
	this->current_state->destroy(this->current_state);

	allocator_free(this);
}

/*
 * Described in header.
 */
ike_sa_t * ike_sa_create(ike_sa_id_t *ike_sa_id)
{
	private_ike_sa_t *this = allocator_alloc_thing(private_ike_sa_t);

	/* Public functions */
	this->protected.public.process_message = (status_t(*)(ike_sa_t*, message_t*)) process_message;
	this->protected.public.initiate_connection = (status_t(*)(ike_sa_t*,connection_t*)) initiate_connection;
	this->protected.public.get_id = (ike_sa_id_t*(*)(ike_sa_t*)) get_id;
	this->protected.public.retransmit_request = (status_t (*) (ike_sa_t *, u_int32_t)) retransmit_request;
	this->protected.public.get_state = (ike_sa_state_t (*) (ike_sa_t *this)) get_state;
	this->protected.public.send_delete_ike_sa_request = (void (*)(ike_sa_t*)) send_delete_ike_sa_request;
	this->protected.public.destroy = (void(*)(ike_sa_t*))destroy;
	
	/* protected functions */
	this->protected.build_message = (void (*) (protected_ike_sa_t *, exchange_type_t , bool , message_t **)) build_message;
	this->protected.get_prf = (prf_t *(*) (protected_ike_sa_t *)) get_prf;	
	this->protected.get_child_prf = (prf_t *(*) (protected_ike_sa_t *)) get_child_prf;
	this->protected.get_prf_auth_i = (prf_t *(*) (protected_ike_sa_t *)) get_prf_auth_i;
	this->protected.get_prf_auth_r = (prf_t *(*) (protected_ike_sa_t *)) get_prf_auth_r;
	this->protected.add_child_sa = (void (*) (protected_ike_sa_t*,child_sa_t*)) add_child_sa;
	this->protected.set_connection = (void (*) (protected_ike_sa_t *,connection_t *)) set_connection;
	this->protected.get_connection = (connection_t *(*) (protected_ike_sa_t *)) get_connection;
	this->protected.set_policy = (void (*) (protected_ike_sa_t *,policy_t *)) set_policy;
	this->protected.get_policy = (policy_t *(*) (protected_ike_sa_t *)) get_policy;
	this->protected.get_randomizer = (randomizer_t *(*) (protected_ike_sa_t *)) get_randomizer;
	this->protected.send_request = (status_t (*) (protected_ike_sa_t *,message_t *)) send_request;
	this->protected.send_response = (status_t (*) (protected_ike_sa_t *,message_t *)) send_response;
	this->protected.send_notify = (void (*)(protected_ike_sa_t*,exchange_type_t,notify_message_type_t,chunk_t)) send_notify;
	this->protected.build_transforms = (status_t (*) (protected_ike_sa_t *,proposal_t*,diffie_hellman_t*,chunk_t,chunk_t)) build_transforms;
	this->protected.set_new_state = (void (*) (protected_ike_sa_t *,state_t *)) set_new_state;
	this->protected.get_crypter_initiator = (crypter_t *(*) (protected_ike_sa_t *)) get_crypter_initiator;
	this->protected.get_signer_initiator = (signer_t *(*) (protected_ike_sa_t *)) get_signer_initiator;	
	this->protected.get_crypter_responder = (crypter_t *(*) (protected_ike_sa_t *)) get_crypter_responder;
	this->protected.get_signer_responder = (signer_t *(*) (protected_ike_sa_t *)) get_signer_responder;	
	this->protected.reset_message_buffers = (void (*) (protected_ike_sa_t *)) reset_message_buffers;
	this->protected.get_last_responded_message = (message_t * (*) (protected_ike_sa_t *this)) get_last_responded_message;
	this->protected.get_last_requested_message = (message_t * (*) (protected_ike_sa_t *this)) get_last_requested_message;
	
	this->protected.set_last_replied_message_id = (void (*) (protected_ike_sa_t *,u_int32_t)) set_last_replied_message_id;
	
	/* private functions */
	this->resend_last_reply = resend_last_reply;

	/* initialize private fields */
	this->logger = charon->logger_manager->get_logger(charon->logger_manager, IKE_SA);
	
	this->ike_sa_id = ike_sa_id->clone(ike_sa_id);
	this->child_sas = linked_list_create();
	this->randomizer = randomizer_create();
	
	this->last_requested_message = NULL;
	this->last_responded_message = NULL;
	this->message_id_out = 0;
	this->message_id_in = 0;
	this->last_replied_message_id = -1;
	this->crypter_initiator = NULL;
	this->crypter_responder = NULL;
	this->signer_initiator = NULL;
	this->signer_responder = NULL;
	this->prf = NULL;
	this->prf_auth_i = NULL;
	this->prf_auth_r = NULL;
	this->child_prf = NULL;
	this->connection = NULL;
	this->policy = NULL;
	
	/* at creation time, IKE_SA is in a initiator state */
	if (ike_sa_id->is_initiator(ike_sa_id))
	{
		this->logger->log(this->logger, CONTROL | LEVEL2, "Create first state_t object of type INITIATOR_INIT");
		this->current_state = (state_t *) initiator_init_create(&(this->protected));
	}
	else
	{
		this->logger->log(this->logger, CONTROL | LEVEL2, "Create first state_t object of type RESPONDER_INIT");
		this->current_state = (state_t *) responder_init_create(&(this->protected));
	}
	return &(this->protected.public);
}
