/**
 * @file ike_auth_requested.c
 * 
 * @brief Implementation of ike_auth_requested_t.
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
 
#include "ike_auth_requested.h"

#include <daemon.h>
#include <utils/allocator.h>
#include <encoding/payloads/ts_payload.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/notify_payload.h>
#include <transforms/signers/signer.h>
#include <transforms/crypters/crypter.h>
#include <sa/states/ike_sa_established.h>
#include <sa/authenticator.h>

typedef struct private_ike_auth_requested_t private_ike_auth_requested_t;

/**
 * Private data of a ike_auth_requested_t object.
 *
 */
struct private_ike_auth_requested_t {
	/**
	 * methods of the state_t interface
	 */
	ike_auth_requested_t public;
	
	/**
	 * Assigned IKE_SA
	 */
	 protected_ike_sa_t *ike_sa;
	 
	/**
	 * SA config, just a copy of the one stored in the ike_sa
	 */
	sa_config_t *sa_config; 
	
	/**
	 * Received nonce from responder
	 */
	chunk_t received_nonce;
	 
	/**
	 * Logger used to log data 
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
	
	/**
	 * process the IDr payload (check if other id is valid)
	 */
	status_t (*process_idr_payload) (private_ike_auth_requested_t *this, id_payload_t *idr_payload);
	
	/**
	 * process the SA payload (check if selected proposals are valid, setup child sa)
	 */
	status_t (*process_sa_payload) (private_ike_auth_requested_t *this, sa_payload_t *sa_payload);
	
	/**
	 * process the AUTH payload (check authenticity of message)
	 */
	status_t (*process_auth_payload) (private_ike_auth_requested_t *this, auth_payload_t *auth_payload, id_payload_t *other_id_payload);
	
	/**
	 * process the TS payload (check if selected traffic selectors are valid)
	 */
	status_t (*process_ts_payload) (private_ike_auth_requested_t *this, bool ts_initiator, ts_payload_t *ts_payload);
	 
};


/**
 * Implements state_t.process_message
 */
static status_t process_message(private_ike_auth_requested_t *this, message_t *ike_auth_reply)
{
	status_t status;
	signer_t *signer;
	crypter_t *crypter;
	iterator_t *payloads;
	exchange_type_t exchange_type;
	id_payload_t *idr_payload = NULL;
	auth_payload_t *auth_payload;
	sa_payload_t *sa_payload;
	ts_payload_t *tsi_payload, *tsr_payload;
	
	exchange_type = ike_auth_reply->get_exchange_type(ike_auth_reply);
	if (exchange_type != IKE_AUTH)
	{
		this->logger->log(this->logger, ERROR | MORE, "Message of type %s not supported in state ike_auth_requested",
							mapping_find(exchange_type_m,exchange_type));
		return FAILED;
	}
	
	if (ike_auth_reply->get_request(ike_auth_reply))
	{
		this->logger->log(this->logger, ERROR | MORE, "Only responses of type IKE_AUTH supported in state ike_auth_requested");
		return FAILED;
	}
	
	/* get signer for verification and crypter for decryption */
	signer = this->ike_sa->get_signer_responder(this->ike_sa);
	crypter = this->ike_sa->get_crypter_responder(this->ike_sa);
	
	/* parse incoming message */
	status = ike_auth_reply->parse_body(ike_auth_reply, crypter, signer);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR | MORE, "Could not parse body of request message");
		return status;
	}
	
	this->sa_config = this->ike_sa->get_sa_config(this->ike_sa);
	
	/* iterate over incoming payloads. Message is verified, we can be sure there are the required payloads */
	payloads = ike_auth_reply->get_payload_iterator(ike_auth_reply);
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		
		switch (payload->get_type(payload))
		{
			case AUTHENTICATION:
			{
				auth_payload = (auth_payload_t*)payload;
				break;	
			}
			case ID_RESPONDER:
			{
				idr_payload = (id_payload_t*)payload;
				break;	
			}
			case SECURITY_ASSOCIATION:
			{
				sa_payload = (sa_payload_t*)payload;
				break;
			}
			case CERTIFICATE:
			{
				/* TODO handle cert payloads */
				break;
			}
			case TRAFFIC_SELECTOR_INITIATOR:
			{
				tsi_payload = (ts_payload_t*)payload;				
				break;	
			}
			case TRAFFIC_SELECTOR_RESPONDER:
			{
				tsr_payload = (ts_payload_t*)payload;
				break;	
			}
			case NOTIFY:
			{
				notify_payload_t *notify_payload = (notify_payload_t *) payload;
				
				
				this->logger->log(this->logger, CONTROL|MORE, "Process notify type %s for protocol %s",
								  mapping_find(notify_message_type_m, notify_payload->get_notify_message_type(notify_payload)),
								  mapping_find(protocol_id_m, notify_payload->get_protocol_id(notify_payload)));
								  
				if (notify_payload->get_protocol_id(notify_payload) != IKE)
				{
					this->logger->log(this->logger, ERROR | MORE, "Notify reply not for IKE protocol.");
					payloads->destroy(payloads);
					return FAILED;	
				}
				
				switch (notify_payload->get_notify_message_type(notify_payload))
				{
					default:
					{
						/*
						 * If an unrecognized Notify type is received, the IKE_SA gets destroyed.
						 * 
						 */
						
						this->logger->log(this->logger, ERROR, "Notify type %s not recognized in state ike_auth_requested.",
										  mapping_find(notify_message_type_m,notify_payload->get_notify_message_type(notify_payload)));
						payloads->destroy(payloads);
						return DELETE_ME;	
					}
				}
			}
			default:
			{
				this->logger->log(this->logger, ERROR, "Payload type %s not supported in state ike_auth_requested!", mapping_find(payload_type_m, payload->get_type(payload)));
				payloads->destroy(payloads);
				return FAILED;
			}
		}
	}
	/* iterator can be destroyed */
	payloads->destroy(payloads);

	/* process all payloads */
	status = this->process_idr_payload(this, idr_payload);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Processing idr payload failed");
		return status;
	}
	status = this->process_sa_payload(this, sa_payload);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Processing sa payload failed");
		return status;
	}
	status = this->process_auth_payload(this, auth_payload,idr_payload);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Processing auth payload failed");
		return status;
	}
	status = this->process_ts_payload(this, TRUE, tsi_payload);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Processing tsi payload failed");
		return status;
	}
	status = this->process_ts_payload(this, FALSE, tsr_payload);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Processing tsr payload failed");
		return status;
	}

	this->ike_sa->set_last_replied_message_id(this->ike_sa,ike_auth_reply->get_message_id(ike_auth_reply));
	this->logger->log(this->logger, CONTROL | MORE, "IKE_AUTH response successfully handled. IKE_SA established.");
	
	/* create new state */
	this->ike_sa->set_new_state(this->ike_sa, (state_t*)ike_sa_established_create(this->ike_sa));

	this->public.state_interface.destroy(&(this->public.state_interface));
	return SUCCESS;
}

/**
 * Implements private_ike_auth_requested_t.process_idr_payload
 */
static status_t process_idr_payload(private_ike_auth_requested_t *this, id_payload_t *idr_payload)
{
	identification_t *other_id, *configured_other_id;
	
	other_id = idr_payload->get_identification(idr_payload);

	configured_other_id = this->sa_config->get_other_id(this->sa_config);
	if (configured_other_id)
	{
		this->logger->log(this->logger, CONTROL, "configured ID: %s, ID of responder: %s",
							configured_other_id->get_string(configured_other_id),
							other_id->get_string(other_id));

		if (!other_id->equals(other_id, configured_other_id))
		{
			other_id->destroy(other_id);
			this->logger->log(this->logger, ERROR, "IKE_AUTH reply didn't contain requested id");
			return FAILED;	
		}
	}
	
	other_id->destroy(other_id);
	/* TODO do we have to store other_id  somewhere ? */
	return SUCCESS;
}

/**
 * Implements private_ike_auth_requested_t.process_sa_payload
 */
static status_t process_sa_payload(private_ike_auth_requested_t *this, sa_payload_t *sa_payload)
{
	child_proposal_t *proposals, *proposal_chosen;
	size_t proposal_count;
	status_t status;
	
	/* dummy spis, until we have a child sa to request them */
	u_int8_t ah_spi[4] = {0x01, 0x02, 0x03, 0x04};
	u_int8_t esp_spi[4] = {0x05, 0x06, 0x07, 0x08};
	
	/* check selected proposal */
	status = sa_payload->get_child_proposals(sa_payload, &proposals, &proposal_count);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "responders sa payload contained no proposals");
		return FAILED;
	}
	if (proposal_count > 1)
	{
		allocator_free(proposals);
		this->logger->log(this->logger, ERROR, "responders sa payload contained more than one proposal");
		return FAILED;
	}
	
	proposal_chosen = this->sa_config->select_proposal(this->sa_config, ah_spi, esp_spi, proposals, proposal_count);
	if (proposal_chosen == NULL)
	{
		this->logger->log(this->logger, ERROR, "responder selected an not offered proposal");
		allocator_free(proposals);
		return FAILED;
	}
	else
	{
		allocator_free(proposal_chosen);
	}
	
	allocator_free(proposals);
	
	return SUCCESS;
}

/**
 * Implements private_ike_auth_requested_t.process_auth_payload
 */
static status_t process_auth_payload(private_ike_auth_requested_t *this, auth_payload_t *auth_payload, id_payload_t *other_id_payload)
{
	
	chunk_t received_auth_data = auth_payload->get_data(auth_payload);
	chunk_t last_message_data = this->ike_sa->get_last_sent_message_data(this->ike_sa);
	bool verified;
	identification_t *identification;
	authenticator_t *authenticator;
	
	identification = other_id_payload->get_identification(other_id_payload);
	
	/* TODO VERIFY auth here */
	authenticator = authenticator_create(this->ike_sa);

	authenticator->verify_authentication(authenticator,auth_payload->get_auth_method(auth_payload),received_auth_data,last_message_data,this->received_nonce,identification,&verified);
	
	authenticator->destroy(authenticator);
	
	allocator_free_chunk(&received_auth_data);
	
	
	/* TODO VERIFY auth here */
	return SUCCESS;	
}

/**
 * Implements private_ike_auth_requested_t.process_ts_payload
 */
static status_t process_ts_payload(private_ike_auth_requested_t *this, bool ts_initiator, ts_payload_t *ts_payload)
{
	traffic_selector_t **ts_received, **ts_selected;
	size_t ts_received_count, ts_selected_count;
	status_t status = SUCCESS;
	
	/* get ts form payload */
	ts_received_count = ts_payload->get_traffic_selectors(ts_payload, &ts_received);
	/* select ts depending on payload type */
	if (ts_initiator)
	{
		ts_selected_count = this->sa_config->select_traffic_selectors_initiator(this->sa_config, ts_received, ts_received_count, &ts_selected);
	}
	else
	{
		ts_selected_count = this->sa_config->select_traffic_selectors_responder(this->sa_config, ts_received, ts_received_count, &ts_selected);
	}
	/* check if the responder selected valid proposals */
	if (ts_selected_count != ts_received_count)
	{
		this->logger->log(this->logger, ERROR, "responder selected invalid traffic selectors");
		status = FAILED;	
	}
	
	/* cleanup */
	while(ts_received_count--) 
	{
		traffic_selector_t *ts = *ts_received + ts_received_count;
		ts->destroy(ts);
	}
	allocator_free(ts_received);
	while(ts_selected_count--) 
	{
		traffic_selector_t *ts = *ts_selected + ts_selected_count;
		ts->destroy(ts);
	}
	allocator_free(ts_selected);
	return status;
}
/**
 * Implements state_t.get_state
 */
static ike_sa_state_t get_state(private_ike_auth_requested_t *this)
{
	return IKE_AUTH_REQUESTED;
}

/**
 * Implements state_t.get_state
 */
static void destroy(private_ike_auth_requested_t *this)
{
	allocator_free_chunk(&(this->received_nonce));
	allocator_free(this);
}

/* 
 * Described in header.
 */
ike_auth_requested_t *ike_auth_requested_create(protected_ike_sa_t *ike_sa, chunk_t received_nonce)
{
	private_ike_auth_requested_t *this = allocator_alloc_thing(private_ike_auth_requested_t);

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* private functions */
	
	this->process_idr_payload = process_idr_payload;
	this->process_sa_payload = process_sa_payload;
	this->process_auth_payload = process_auth_payload;
	this->process_ts_payload = process_ts_payload;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->received_nonce = received_nonce;
	this->logger = this->ike_sa->get_logger(this->ike_sa);
	
	return &(this->public);
}
