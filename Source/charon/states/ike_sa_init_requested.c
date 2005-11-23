/**
 * @file ike_sa_init_requested.c
 * 
 * @brief State of a IKE_SA after requesting an IKE_SA_INIT 
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
 
#include "ike_sa_init_requested.h"

#include "../globals.h"
#include "../utils/allocator.h"
#include "../transforms/diffie_hellman.h"
#include "../payloads/sa_payload.h"
#include "../payloads/ke_payload.h"
#include "../payloads/nonce_payload.h"

/**
 * Private data of a ike_sa_init_requested_t object.
 *
 */
typedef struct private_ike_sa_init_requested_s private_ike_sa_init_requested_t;
struct private_ike_sa_init_requested_s {
	/**
	 * methods of the state_t interface
	 */
	ike_sa_init_requested_t public;
	
	/** 
	 * Assigned IKE_SA
	 */
	protected_ike_sa_t *ike_sa;
	
	/**
	 * Diffie Hellman object used to compute shared secret
	 */
	diffie_hellman_t *diffie_hellman;
	
	/**
	 * Shared secret of successful exchange
	 */
	chunk_t shared_secret;
	
	/**
	 * Sent nonce value
	 */
	chunk_t sent_nonce;
	
	/**
	 * Received nonce
	 */
	chunk_t received_nonce;
	
	/**
	 * DH group priority used to get dh_group_number from configuration manager.
	 * 
	 * Currently uused but usable if informational messages of unsupported dh group number are processed.
	 */
	u_int16_t dh_group_priority;
	
	/**
	 * Logger used to log data 
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
};

/**
 * Implements state_t.get_state
 */
static status_t process_message(private_ike_sa_init_requested_t *this, message_t *message, state_t **new_state)
{
	status_t 				status;
	linked_list_iterator_t 	*payloads;
	exchange_type_t			exchange_type;
	u_int64_t 				responder_spi;

	exchange_type = message->get_exchange_type(message);
	if (exchange_type != IKE_SA_INIT)
	{
		this->logger->log(this->logger, ERROR | MORE, "Message of type %s not supported in state ike_sa_init_requested",mapping_find(exchange_type_m,exchange_type));
		return FAILED;
	}
	
	if (message->get_request(message))
	{
		this->logger->log(this->logger, ERROR | MORE, "Only responses of type IKE_SA_INIT supported in state ike_sa_init_requested");
		return FAILED;
	}
	
	/* parse incoming message */
	status = message->parse_body(message);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR | MORE, "Could not parse body");
		return status;	
	}
	
	responder_spi = message->get_responder_spi(message);
	this->ike_sa->ike_sa_id->set_responder_spi(this->ike_sa->ike_sa_id,responder_spi);
	
	/* iterate over incoming payloads */
	status = message->get_payload_iterator(message, &payloads);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not create payload interator");
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
				sa_payload_t 				*sa_payload = (sa_payload_t*)payload;
				linked_list_iterator_t 		*suggested_proposals;
				encryption_algorithm_t		encryption_algorithm = ENCR_UNDEFINED;
				pseudo_random_function_t		pseudo_random_function = PRF_UNDEFINED;
				integrity_algorithm_t		integrity_algorithm = AUTH_UNDEFINED;

				/* get the list of suggested proposals */ 
				status = sa_payload->create_proposal_substructure_iterator(sa_payload, &suggested_proposals, TRUE);
				if (status != SUCCESS)
				{	
					this->logger->log(this->logger, ERROR, "Fatal errror: Could not create iterator on suggested proposals");
					payloads->destroy(payloads);
					return status;
				}
				
				/* now let the configuration-manager return the transforms for the given proposal*/
				this->logger->log(this->logger, CONTROL | MOST, "Get transforms for suggested proposal");
				status = global_configuration_manager->get_transforms_for_host_and_proposals(global_configuration_manager,
									this->ike_sa->other.host, suggested_proposals, &encryption_algorithm,&pseudo_random_function,&integrity_algorithm);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR | MORE, "Suggested proposals not supported!");
					suggested_proposals->destroy(suggested_proposals);
					payloads->destroy(payloads);
					return status;
				}
				suggested_proposals->destroy(suggested_proposals);
				
				this->ike_sa->prf = prf_create(pseudo_random_function);
				if (this->ike_sa->prf == NULL)
				{
					this->logger->log(this->logger, ERROR | MORE, "PRF type not supported");
					payloads->destroy(payloads);
					return FAILED;
				}
				

				/* ok, we have what we need for sa_payload */
				break;
			}
			case KEY_EXCHANGE:
			{
				ke_payload_t *ke_payload = (ke_payload_t*)payload;
		
				status = this->diffie_hellman->set_other_public_value(this->diffie_hellman, ke_payload->get_key_exchange_data(ke_payload));
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR, "Could not set other public value for DH exchange. Status %s",mapping_find(status_m,status));
					payloads->destroy(payloads);
					return OUT_OF_RES;
				}
				
				/* shared secret is computed AFTER processing of all payloads... */				
				break;
			}
			case NONCE:
			{
				nonce_payload_t 	*nonce_payload = (nonce_payload_t*)payload;
								
				if (this->received_nonce.ptr != NULL)
				{
					this->logger->log(this->logger, CONTROL | MOST, "Destroy existing received nonce");
					allocator_free(this->received_nonce.ptr);
					this->received_nonce.ptr = NULL;
					this->received_nonce.len = 0;
				}

				status = nonce_payload->get_nonce(nonce_payload, &(this->received_nonce));
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR, "Fatal error: Could not get received nonce");
					payloads->destroy(payloads);
					return OUT_OF_RES;
				}
				
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR, "Fatal errror: Payload type not supported!!!!");
				payloads->destroy(payloads);
				return FAILED;
			}
				
		}
			
	}
	payloads->destroy(payloads);

	if (this->shared_secret.ptr != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy existing shared_secret");
		allocator_free(this->shared_secret.ptr);
		this->shared_secret.ptr = NULL;
		this->shared_secret.len = 0;
	}


	/* store shared secret  */
	this->logger->log(this->logger, CONTROL | MOST, "Retrieve shared secret and store it");
	status = this->diffie_hellman->get_shared_secret(this->diffie_hellman, &(this->shared_secret));		
	this->logger->log_chunk(this->logger, PRIVATE, "Shared secret", &this->shared_secret);
	
	status = this->ike_sa->compute_secrets(this->ike_sa,this->shared_secret,this->sent_nonce, this->received_nonce);
	if (status != SUCCESS)
	{
		/* secrets could not be computed */
		this->logger->log(this->logger, ERROR | MORE, "Secrets could not be computed!");
		return status;
	}
	
	
	

	/****************************
	 * 
	 *  TODO
	 * 
	 * Create PRF+ object
	 * 
	 * Create Keys for next process
	 * 
	 * Send IKE_SA_AUTH request
	 * 
	 ****************************/


	/* set up the reply */
//	status = this->ike_sa->build_message(this->ike_sa, IKE_SA_INIT, FALSE, &response);
//	if (status != SUCCESS)
//	{
//		return status;	
//	}

//	response->destroy(response);

	*new_state = (state_t *) this;
	
	return SUCCESS;
}

/**
 * Implements state_t.get_state
 */
static ike_sa_state_t get_state(private_ike_sa_init_requested_t *this)
{
	return IKE_SA_INIT_REQUESTED;
}

/**
 * Implements state_t.get_state
 */
static status_t destroy(private_ike_sa_init_requested_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy state of type ike_sa_init_requested_t");
	
	this->logger->log(this->logger, CONTROL | MOST, "Destroy diffie hellman object");
	this->diffie_hellman->destroy(this->diffie_hellman);
	if (this->sent_nonce.ptr != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy sent nonce");
		allocator_free(this->sent_nonce.ptr);
	}
	if (this->received_nonce.ptr != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy received nonce");
		allocator_free(this->received_nonce.ptr);
	}

	if (this->shared_secret.ptr != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy shared secret");
		allocator_free(this->shared_secret.ptr);
	}
	
	allocator_free(this);
	return SUCCESS;
}

/* 
 * Described in header.
 */
ike_sa_init_requested_t *ike_sa_init_requested_create(protected_ike_sa_t *ike_sa,u_int16_t dh_group_priority, diffie_hellman_t *diffie_hellman, chunk_t sent_nonce)
{
	private_ike_sa_init_requested_t *this = allocator_alloc_thing(private_ike_sa_init_requested_t);
	
	if (this == NULL)
	{
		return NULL;
	}

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *,state_t **)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (status_t (*) (state_t *)) destroy;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->received_nonce.ptr = NULL;
	this->received_nonce.len = 0;
	this->shared_secret.ptr = NULL;
	this->shared_secret.len = 0;
	this->logger = this->ike_sa->logger;
	this->diffie_hellman = diffie_hellman;
	this->sent_nonce = sent_nonce;
	this->dh_group_priority = dh_group_priority;
	
	return &(this->public);
}
