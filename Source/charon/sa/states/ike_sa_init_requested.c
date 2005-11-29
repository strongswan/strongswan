/**
 * @file ike_sa_init_requested.c
 * 
 * @brief Implementation of ike_sa_init_requested_t.
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

#include <globals.h>
#include <utils/allocator.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <transforms/diffie_hellman.h>


typedef struct private_ike_sa_init_requested_t private_ike_sa_init_requested_t;

/**
 * Private data of a ike_sa_init_requested_t object.
 *
 */
struct private_ike_sa_init_requested_t {
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
static status_t process_message(private_ike_sa_init_requested_t *this, message_t *message)
{
	status_t status;
	iterator_t *payloads;
	exchange_type_t	exchange_type;
	u_int64_t responder_spi;
	ike_sa_id_t *ike_sa_id;
	

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
	status = message->parse_body(message, NULL, NULL);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR | MORE, "Could not parse body");
		return status;	
	}
	
	responder_spi = message->get_responder_spi(message);
	ike_sa_id = this->ike_sa->public.get_id(&(this->ike_sa->public));
	ike_sa_id->set_responder_spi(ike_sa_id,responder_spi);
	
	/* iterate over incoming payloads */
	message->get_payload_iterator(message, &payloads);
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
				iterator_t 	*suggested_proposals;
				proposal_substructure_t *suggested_proposal;			
				bool valid;
				
				
				/* get the list of suggested proposals */ 
				sa_payload->create_proposal_substructure_iterator(sa_payload, &suggested_proposals, TRUE);

				
				/* now let the configuration-manager check the selected proposals*/
				this->logger->log(this->logger, CONTROL | MOST, "Check suggested proposals");
				status = global_configuration_manager->check_selected_proposals_for_host(global_configuration_manager,
									this->ike_sa->get_other_host(this->ike_sa), suggested_proposals,&valid);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR | MORE, "Could not check suggested proposals!");
					suggested_proposals->destroy(suggested_proposals);
					payloads->destroy(payloads);
					return status;
				}

				if (!valid)
				{
					this->logger->log(this->logger, ERROR | MORE, "Suggested proposals not accepted!");
					payloads->destroy(payloads);
					return status;
				}


				/* let the ike_sa create their own transforms from proposal informations */
				suggested_proposals->reset(suggested_proposals);
				/* TODO check for true*/
				suggested_proposals->has_next(suggested_proposals);
				status = suggested_proposals->current(suggested_proposals,(void **)&suggested_proposal);
				suggested_proposals->destroy(suggested_proposals);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR | MORE, "Could not get first proposal");
					payloads->destroy(payloads);
					return status;
				}
								
				status = this->ike_sa->create_transforms_from_proposal(this->ike_sa,suggested_proposal);	
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR | MORE, "Transform objects could not be created from selected proposal");
					payloads->destroy(payloads);
					return status;
				}
				

				/* ok, we have what we need for sa_payload */
				break;
			}
			case KEY_EXCHANGE:
			{
				ke_payload_t *ke_payload = (ke_payload_t*)payload;
				
				this->diffie_hellman->set_other_public_value(this->diffie_hellman, ke_payload->get_key_exchange_data(ke_payload));
				
				/* shared secret is computed AFTER processing of all payloads... */				
				break;
			}
			case NONCE:
			{
				nonce_payload_t 	*nonce_payload = (nonce_payload_t*)payload;
				
				allocator_free(this->received_nonce.ptr);
				this->received_nonce = CHUNK_INITIALIZER;
				
				nonce_payload->get_nonce(nonce_payload, &(this->received_nonce));
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR, "Payload type not supported!!!!");
				payloads->destroy(payloads);
				return FAILED;
			}
				
		}
			
	}
	payloads->destroy(payloads);
	
	allocator_free(this->shared_secret.ptr);
	this->shared_secret = CHUNK_INITIALIZER;
	
	/* store shared secret  */
	this->logger->log(this->logger, CONTROL | MOST, "Retrieve shared secret and store it");
	status = this->diffie_hellman->get_shared_secret(this->diffie_hellman, &(this->shared_secret));		
	this->logger->log_chunk(this->logger, PRIVATE, "Shared secret", &this->shared_secret);
	
	this->ike_sa->compute_secrets(this->ike_sa,this->shared_secret,this->sent_nonce, this->received_nonce);

	/****************************
	 * 
	 *  TODO
	 * 
	 * Send IKE_SA_AUTH request
	 * 
	 * Make state change
	 * 
	 ****************************/


	/* set up the reply */
//	status = this->ike_sa->build_message(this->ike_sa, IKE_SA_INIT, FALSE, &response);
//	if (status != SUCCESS)
//	{
//		return status;	
//	}

//	response->destroy(response);

	
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
static void destroy(private_ike_sa_init_requested_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy state of type ike_sa_init_requested_t");
	
	this->logger->log(this->logger, CONTROL | MOST, "Destroy diffie hellman object");
	this->diffie_hellman->destroy(this->diffie_hellman);
	
	allocator_free(this->sent_nonce.ptr);
	allocator_free(this->received_nonce.ptr);
	allocator_free(this->shared_secret.ptr);
	allocator_free(this);
}

/* 
 * Described in header.
 */
ike_sa_init_requested_t *ike_sa_init_requested_create(protected_ike_sa_t *ike_sa,u_int16_t dh_group_priority, diffie_hellman_t *diffie_hellman, chunk_t sent_nonce)
{
	private_ike_sa_init_requested_t *this = allocator_alloc_thing(private_ike_sa_init_requested_t);
	
	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->received_nonce = CHUNK_INITIALIZER;
	this->shared_secret = CHUNK_INITIALIZER;
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	this->diffie_hellman = diffie_hellman;
	this->sent_nonce = sent_nonce;
	this->dh_group_priority = dh_group_priority;
	
	return &(this->public);
}
