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
	 * Sent nonce value
	 */
	chunk_t sent_nonce;
	
	/**
	 * Received nonce
	 */
	chunk_t received_nonce;
	
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
	status_t status;
	linked_list_iterator_t *payloads;
	message_t *response;

	
	/* parse incoming message */
	status = message->parse_body(message);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not parse body");
		return status;	
	}
	/* iterate over incoming payloads */
	status = message->get_payload_iterator(message, &payloads);
	if (status != SUCCESS)
	{
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
				
				dh = this->diffie_hellman;

			
				status = dh->set_other_public_value(dh, ke_payload->get_key_exchange_data(ke_payload));
				if (status != SUCCESS)
				{
					dh->destroy(dh);
					payloads->destroy(payloads);
					return OUT_OF_RES;
				}
				
				status = dh->get_shared_secret(dh, &shared_secret);
					
				this->logger->log_chunk(this->logger, RAW, "Shared secret", &shared_secret);
				
				allocator_free_chunk(shared_secret);
				
				break;
			}
			case NONCE:
			{
				nonce_payload_t *nonce_payload = (nonce_payload_t*)payload;
				chunk_t nonce;
				
				nonce_payload->get_nonce(nonce_payload, &nonce);
				/** @todo free if there is already one */
				this->received_nonce.ptr = allocator_clone_bytes(nonce.ptr, nonce.len);
				this->received_nonce.len = nonce.len;
				if (this->received_nonce.ptr == NULL)
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


	/* set up the reply */
//	status = this->ike_sa->build_message(this->ike_sa, IKE_SA_INIT, FALSE, &response);
//	if (status != SUCCESS)
//	{
//		return status;	
//	}

//	response->destroy(response);

	*new_state = this;
	
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
	
	allocator_free(this);
	return SUCCESS;
}

/* 
 * Described in header.
 */
ike_sa_init_requested_t *ike_sa_init_requested_create(protected_ike_sa_t *ike_sa, diffie_hellman_t *diffie_hellman, chunk_t sent_nonce)
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
	this->logger = this->ike_sa->logger;
	this->diffie_hellman = diffie_hellman;
	this->sent_nonce = sent_nonce;
	
	return &(this->public);
}
