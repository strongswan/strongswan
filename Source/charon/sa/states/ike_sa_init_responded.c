/**
 * @file ike_sa_init_responded.c
 * 
 * @brief State of a IKE_SA after responding to an IKE_SA_INIT request
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
 
#include "ike_sa_init_responded.h"

#include <utils/allocator.h>
#include <transforms/signers/signer.h>
#include <transforms/crypters/crypter.h>


typedef struct private_ike_sa_init_responded_t private_ike_sa_init_responded_t;

/**
 * Private data of a ike_sa_init_responded_t object.
 *
 */
struct private_ike_sa_init_responded_t {
	/**
	 * methods of the state_t interface
	 */
	ike_sa_init_responded_t public;
	
	/**
	 * Shared secret from DH-Exchange
	 * 
	 * All needed secrets are derived from this shared secret and then passed to the next
	 * state of type ike_sa_established_t
	 */
	chunk_t shared_secret;
	
	/**
	 * Sent nonce used to calculate secrets
	 */
	chunk_t received_nonce;
	
	/**
	 * Sent nonce used to calculate secrets
	 */
	chunk_t sent_nonce;
	
	/**
	 * Assigned IKE_SA
	 */
	protected_ike_sa_t *ike_sa;
	
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
static status_t process_message(private_ike_sa_init_responded_t *this, message_t *message)
{
	status_t status;
	signer_t *signer;
	crypter_t *crypter;
	iterator_t *payloads;
	exchange_type_t exchange_type;
	

	exchange_type = message->get_exchange_type(message);
	if (exchange_type != IKE_AUTH)
	{
		this->logger->log(this->logger, ERROR | MORE, "Message of type %s not supported in state ike_sa_init_responded",
							mapping_find(exchange_type_m,exchange_type));
		return FAILED;
	}
	
	if (!message->get_request(message))
	{
		this->logger->log(this->logger, ERROR | MORE, "Only requests of type IKE_AUTH supported in state ike_sa_init_responded");
		return FAILED;
	}
	
	
	/* get signer for verification and crypter for decryption */
	signer = this->ike_sa->get_signer_initiator(this->ike_sa);
	crypter = this->ike_sa->get_crypter_initiator(this->ike_sa);
	
	/* parse incoming message */
	status = message->parse_body(message, crypter, signer);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR | MORE, "Could not parse body of request message");
		return status;
	}
	
	/* iterate over incoming payloads. We can be sure, the message contains only accepted payloads! */
	payloads = message->get_payload_iterator(message);
	
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		
		/* get current payload */
		payloads->current(payloads, (void**)&payload);
		
		this->logger->log(this->logger, CONTROL|MORE, "Processing payload of type %s", mapping_find(payload_type_m, payload->get_type(payload)));
		switch (payload->get_type(payload))
		{
//			case SECURITY_ASSOCIATION:
//			{
//				sa_payload_t *sa_payload = (sa_payload_t*)payload;
//				iterator_t *suggested_proposals, *accepted_proposals;
//				proposal_substructure_t *accepted_proposal;
//				
//				accepted_proposals = this->proposals->create_iterator(this->proposals, FALSE);
//				
//				/* get the list of suggested proposals */ 
//				suggested_proposals = sa_payload->create_proposal_substructure_iterator(sa_payload, TRUE);
//				
//				/* now let the configuration-manager select a subset of the proposals */
//				status = charon->configuration_manager->select_proposals_for_host(charon->configuration_manager,
//									this->ike_sa->get_other_host(this->ike_sa), suggested_proposals, accepted_proposals);
//				if (status != SUCCESS)
//				{
//					this->logger->log(this->logger, CONTROL | MORE, "No proposal of suggested proposals selected");
//					suggested_proposals->destroy(suggested_proposals);
//					accepted_proposals->destroy(accepted_proposals);
//					payloads->destroy(payloads);
//					return status;
//				}
//				
//				/* iterators are not needed anymore */			
//				suggested_proposals->destroy(suggested_proposals);
//				
//				/* let the ike_sa create their own transforms from proposal informations */
//				accepted_proposals->reset(accepted_proposals);
//				/* TODO check for true*/
//				accepted_proposals->has_next(accepted_proposals);
//				status = accepted_proposals->current(accepted_proposals,(void **)&accepted_proposal);
//				if (status != SUCCESS)
//				{
//					this->logger->log(this->logger, ERROR | MORE, "Accepted proposals not supported?!");
//					accepted_proposals->destroy(accepted_proposals);
//					payloads->destroy(payloads);
//					return status;
//				}
//				
//				status = this->ike_sa->create_transforms_from_proposal(this->ike_sa,accepted_proposal);	
//				accepted_proposals->destroy(accepted_proposals);
//				if (status != SUCCESS)
//				{
//					this->logger->log(this->logger, ERROR | MORE, "Transform objects could not be created from selected proposal");
//					payloads->destroy(payloads);
//					return status;
//				}
//				
//				this->logger->log(this->logger, CONTROL | MORE, "SA Payload processed");
//				/* ok, we have what we need for sa_payload (proposals are stored in this->proposals)*/
//				break;
//			}
	
			default:
			{
				this->logger->log(this->logger, ERROR | MORE, "Payload type not supported!");
				payloads->destroy(payloads);
				return NOT_SUPPORTED;
			}
		}
	}
	/* iterator can be destroyed */
	payloads->destroy(payloads);
	
	
	
	this->logger->log(this->logger, CONTROL | MORE, "Request successfully handled. Going to create reply.");

	this->logger->log(this->logger, CONTROL | MOST, "Going to create nonce.");	
	
	
	return SUCCESS;
}

/**
 * Implements state_t.get_state
 */
static ike_sa_state_t get_state(private_ike_sa_init_responded_t *this)
{
	return IKE_SA_INIT_RESPONDED;
}

/**
 * Implements state_t.get_state
 */
static void destroy(private_ike_sa_init_responded_t *this)
{
	this->logger->log(this->logger, CONTROL | MORE, "Going to destroy ike_sa_init_responded_t state object");
	
	this->logger->log(this->logger, CONTROL | MOST, "Destroy shared_secret");
	allocator_free(this->shared_secret.ptr);

	this->logger->log(this->logger, CONTROL | MOST, "Destroy sent nonce");
	allocator_free(this->sent_nonce.ptr);

	this->logger->log(this->logger, CONTROL | MOST, "Destroy received nonce");
	allocator_free(this->received_nonce.ptr);
	
	allocator_free(this);
}

/* 
 * Described in header.
 */
 
ike_sa_init_responded_t *ike_sa_init_responded_create(protected_ike_sa_t *ike_sa, chunk_t shared_secret, chunk_t received_nonce, chunk_t sent_nonce)
{
	private_ike_sa_init_responded_t *this = allocator_alloc_thing(private_ike_sa_init_responded_t);

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	this->shared_secret = shared_secret;
	this->received_nonce = received_nonce;
	this->sent_nonce = sent_nonce;
	
	return &(this->public);
}
