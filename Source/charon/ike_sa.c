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


/**
 * Nonce size in bytes of all sent nonces
 */
#define NONCE_SIZE 16

/**
 * States in which a IKE_SA can actually be
 */
typedef enum ike_sa_state_e ike_sa_state_t;

enum ike_sa_state_e {

	/**
	 * IKE_SA is is not in a state
	 */
	NO_STATE = 1,

	/**
	 * A IKE_SA_INIT-message was sent: role initiator
	 */
	IKE_SA_INIT_REQUESTED = 2,

	/**
	 * A IKE_SA_INIT-message was replied: role responder
	 */
	IKE_SA_INIT_RESPONDED = 3,

	/**
	 * An IKE_AUTH-message was sent after a successful
	 * IKE_SA_INIT-exchange: role initiator
	 */
	IKE_AUTH_REQUESTED = 4,

	/**
	 * An IKE_AUTH-message was replied: role responder.
	 * In this state, all the informations for an IKE_SA
	 * and one CHILD_SA are known.
	 */
	IKE_SA_INITIALIZED = 5
};

/**
 * string mappings for ike_sa_state 
 */
mapping_t ike_sa_state_m[] = {
	{NO_STATE, "NO_STATE"},
	{IKE_SA_INIT_REQUESTED, "IKE_SA_INIT_REQUESTED"},
	{IKE_SA_INIT_RESPONDED, "IKE_SA_INIT_RESPONDED"},
	{IKE_AUTH_REQUESTED, "IKE_AUTH_REQUESTED"},
	{IKE_SA_INITIALIZED, "IKE_SA_INITIALIZED"},
	{MAPPING_END, NULL}
};


/**
 * Private data of an message_t object
 */
typedef struct private_ike_sa_s private_ike_sa_t;

struct private_ike_sa_s {

	/**
	 * Public part of a ike_sa_t object
	 */
	ike_sa_t public;
	
	/**
	 * Builds an empty IKEv2-Message
	 * 
	 * Depending on the type of message (request or response), the message id is 
	 * either message_id_out or message_id_in.
	 * 
	 * 
	 * @param this		calling object
	 * @param type		exchange type of new message
	 * @param request	TRUE, if message has to be a request
	 * @param message	new message is stored at this location
	 * @return			
	 * 					- SUCCESS
	 * 					- OUT_OF_RES
	 */
	status_t (*build_message) (private_ike_sa_t *this, exchange_type_t type, bool request, message_t **message);

	status_t (*build_sa_payload) (private_ike_sa_t *this, sa_payload_t **payload);
	status_t (*build_ke_payload) (private_ike_sa_t *this, ke_payload_t **payload);
	status_t (*build_nonce_payload) (private_ike_sa_t *this, nonce_payload_t **payload);
	
	status_t (*create_delete_job) (private_ike_sa_t *this);
	status_t (*resend_last_reply) (private_ike_sa_t *this);
	
	
	status_t (*transto_ike_sa_init_requested) (private_ike_sa_t *this, char *name);
	status_t (*transto_ike_sa_init_responded) (private_ike_sa_t *this, message_t *message);
	status_t (*transto_ike_auth_requested) (private_ike_sa_t *this, message_t *message);

	/* Private values */
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
	ike_sa_state_t state;
	
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
	
	
	struct {
		/**
		 * Diffie Hellman object used to compute shared secret
		 */
		diffie_hellman_t *diffie_hellman;
		
		/**
		 * Diffie Hellman group number
		 */
		u_int16_t dh_group_number;	
		
		/**
		 * Priority used get matching dh_group number
		 */
		u_int16_t dh_group_priority;
		
		/**
		 * selected proposals
		 */
		linked_list_t *proposals;
		
		/**
		 * Sent nonce value
		 */
		 chunk_t sent_nonce;
		
		/**
		 * received nonce value
		 */
		 chunk_t received_nonce;
	} ike_sa_init_data;
	

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
 * @brief implements function process_message of private_ike_sa_t
 */
static status_t process_message (private_ike_sa_t *this, message_t *message)
{	
	u_int32_t message_id;
	bool is_request;
	exchange_type_t exchange_type;
	/* we must process each request or response from remote host 
	 * the check if a given message is possible for a given state is done in here
	 */

	/* find out type of message (request or response) */
	is_request = message->get_request(message);
	exchange_type = message->get_exchange_type(message);

	this->logger->log(this->logger, CONTROL|MORE, "Process %s message of exchange type %s",(is_request) ? "REQUEST" : "RESPONSE",
						mapping_find(exchange_type_m,exchange_type));

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
	
	/* Now, the exchange type is checked and the appropriate transition handler is called*/	
	switch (message->get_exchange_type(message))
	{
		case IKE_SA_INIT:
		{

			if (message->get_request(message)) {
				if (this->state == 	NO_STATE)
				{
					/* state transission NO_STATE => IKE_SA_INIT_RESPONDED */
					return this->transto_ike_sa_init_responded(this, message);
				}
			}
			else
			{
				if (this->state == IKE_SA_INIT_REQUESTED)
				{
					/* state transission IKE_SA_INIT_REQUESTED => IKE_AUTH_REQUESTED*/
					return this->transto_ike_auth_requested(this, message);
				}
			}
			
			this->logger->log(this->logger, ERROR | MORE, "Message in current state %s not supported",mapping_find(ike_sa_state_m,this->state));	
			
			break;
		}
		case IKE_AUTH:
		{
			if (this->state <= IKE_SA_INIT_REQUESTED)
			{
				this->logger->log(this->logger, ERROR | MORE, "Current state %s of IKE_SA does not allow IKE_AUTH message",mapping_find(ike_sa_state_m,this->state));	
				return FAILED;
			}
			break;
		}
		case CREATE_CHILD_SA:
		{
			if (this->state < IKE_SA_INITIALIZED)
			{
				this->logger->log(this->logger, ERROR | MORE, "Current state %s of IKE_SA does not allow CREATE_CHILD_SA message",mapping_find(ike_sa_state_m,this->state));	
				return FAILED;
			}
			break;
		}
		case INFORMATIONAL:
		{
			break;
		}
		default:
		{
			this->logger->log(this->logger, ERROR, "processing %s-message not supported.",
								mapping_find(exchange_type_m,message->get_exchange_type(message)));
			return NOT_SUPPORTED;
		}
	}
	this->logger->log(this->logger, CONTROL, "received %s-message in state %s, not handled.",
								mapping_find(exchange_type_m, message->get_exchange_type(message)),
								mapping_find(ike_sa_state_m, this->state));
	return INVALID_STATE;
}

/**
 * @brief Implements function build_message of private_ike_sa_t.
 */
static status_t build_message(private_ike_sa_t *this, exchange_type_t type, bool request, message_t **message)
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
 * @brief Implements function transto_ike_sa_init_requested of private_ike_sa_t.
 */
static status_t transto_ike_sa_init_requested(private_ike_sa_t *this, char *name)
{
	message_t *message;
	payload_t *payload;
	packet_t *packet;
	status_t status;
	linked_list_iterator_t *proposal_iterator;
	
	this->logger->log(this->logger, CONTROL, "Initializing connection %s",name);
	
	status = global_configuration_manager->get_local_host(global_configuration_manager, name, &(this->me.host));
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR | MORE, "Could not retrieve local host configuration information for %s",name);
		return INVALID_ARG;
	}
	
	status = global_configuration_manager->get_remote_host(global_configuration_manager, name, &(this->other.host));
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR | MORE, "Could not retrieve remote host configuration information for %s",name);
		return INVALID_ARG;
	}
	
	status = global_configuration_manager->get_dh_group_number(global_configuration_manager, name, &(this->ike_sa_init_data.dh_group_number), this->ike_sa_init_data.dh_group_priority);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR | MORE, "Could not retrieve DH group number for %s",name);
		return INVALID_ARG;
	}
	
	if (this->ike_sa_init_data.proposals->get_count(this->ike_sa_init_data.proposals) > 0)
	{
		this->logger->log(this->logger, ERROR, "Proposals allready existing!");
		return FAILED;		
	}

	status = this->ike_sa_init_data.proposals->create_iterator(this->ike_sa_init_data.proposals, &proposal_iterator, FALSE);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: Could not create iterator on list for proposals");
		return status;	
	}
	
	status = global_configuration_manager->get_proposals_for_host(global_configuration_manager, this->other.host, proposal_iterator);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR | MORE, "Could not retrieve Proposals for %s",name);
		return status;
	}
	/* not needed anymore */
	proposal_iterator->destroy(proposal_iterator);
	
	if (this->ike_sa_init_data.diffie_hellman != NULL)
	{
		this->logger->log(this->logger, ERROR, "Object of type diffie_hellman_t already existing!");
		return FAILED;
	}
	this	->logger->log(this->logger, CONTROL|MOST, "create diffie hellman object");
	this->ike_sa_init_data.diffie_hellman = diffie_hellman_create(this->ike_sa_init_data.dh_group_number);
	if (this->ike_sa_init_data.diffie_hellman == NULL)
	{
		this->logger->log(this->logger, ERROR, "Object of type diffie_hellman_t could not be created!");
		return FAILED;			
	}
	
	if (this->ike_sa_init_data.sent_nonce.ptr != NULL)
	{
		this->logger->log(this->logger, ERROR, "Nonce for IKE_SA_INIT phase already existing!");
		return FAILED;	
	}
		
	if (this->randomizer->allocate_pseudo_random_bytes(this->randomizer, NONCE_SIZE, &(this->ike_sa_init_data.sent_nonce)) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not create nonce!");
		return OUT_OF_RES;
	}
		
	
	/* going to build message */
	status = this->build_message(this, IKE_SA_INIT, TRUE, &message);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not build message");
		return status;
	}

	/* build SA payload */		
	status = this->build_sa_payload(this, (sa_payload_t**)&payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not build SA payload");
		message->destroy(message);
		return status;
	}
	
	this	->logger->log(this->logger, CONTROL|MOST, "add SA payload to message");
	status = message->add_payload(message, payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not add SA payload to message");
		message->destroy(message);
		return status;
	}

	
	/* build KE payload */
	status = this->build_ke_payload(this,(ke_payload_t **) &payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not build KE payload");
		message->destroy(message);
		return status;
	}

	this	->logger->log(this->logger, CONTROL|MOST, "add KE payload to message");
	status = message->add_payload(message, payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not add KE payload to message");
		message->destroy(message);
		return status;
	}
	
	/* build Nonce payload */
	status = this->build_nonce_payload(this, (nonce_payload_t**)&payload);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not build NONCE payload");
		message->destroy(message);
		return status;
	}

	this	->logger->log(this->logger, CONTROL|MOST, "add nonce payload to message");
	status = message->add_payload(message, payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not add nonce payload to message");
		message->destroy(message);
		return status;
	}

	/* generate packet */	
	this	->logger->log(this->logger, CONTROL|MOST, "generate packet from message");
	status = message->generate(message, &packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: could not generate packet from message");
		message->destroy(message);
		return status;
	}
	
	this	->logger->log(this->logger, CONTROL|MOST, "Add packet to global send queue");
	status = global_send_queue->add(global_send_queue, packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not add packet to send queue");
		message->destroy(message);
		return status;
	}

	if (	this->last_requested_message != NULL)
	{
		/* destroy message */
		this	->logger->log(this->logger, CONTROL|MOST, "Destroy stored last requested message");
		this->last_requested_message->destroy(this->last_requested_message);
	}

	this->last_requested_message	 = message;

	/* message counter can now be increased */
	this->message_id_out++;
	
	/* state has NOW changed :-) */
	this	->logger->log(this->logger, CONTROL|MORE, "Change state of IKE_SA from %s to %s",mapping_find(ike_sa_state_m,this->state),mapping_find(ike_sa_state_m,IKE_SA_INIT_REQUESTED) );
	this->state = IKE_SA_INIT_REQUESTED;

	return SUCCESS;
}

static status_t transto_ike_sa_init_responded(private_ike_sa_t *this, message_t *request)
{
	status_t status;
	linked_list_iterator_t *payloads;
	message_t *response;
	host_t *source, *destination;
	payload_t *payload;
	packet_t *packet;
	
	/* this is the first message we process, so copy host infos */
	request->get_source(request, &source);
	request->get_destination(request, &destination);
	/* we need to clone them, since we destroy the message later */
	destination->clone(destination, &(this->me.host));
	source->clone(source, &(this->other.host));
	
	/* parse incoming message */
	status = request->parse_body(request);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR | MORE, "Could not parse body of request message");
		this->create_delete_job(this);
		return status;	
	}

	/* iterate over incoming payloads. We can be sure, the message contains only accepted payloads! */
	status = request->get_payload_iterator(request, &payloads);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: Could not get payload interator");
		this->create_delete_job(this);
		return status;
	}
	
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		
		/* get current payload */
		payloads->current(payloads, (void**)&payload);
		
		this->logger->log(this->logger, CONTROL|MORE, "Processing payload of type %s", mapping_find(payload_type_m, payload->get_type(payload)));
		switch (payload->get_type(payload))
		{
			case SECURITY_ASSOCIATION:
			{
				sa_payload_t *sa_payload = (sa_payload_t*)payload;
				linked_list_iterator_t *suggested_proposals, *accepted_proposals;

				status = this->ike_sa_init_data.proposals->create_iterator(this->ike_sa_init_data.proposals, &accepted_proposals, FALSE);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR, "Fatal error: Could not create iterator on list for proposals");
					payloads->destroy(payloads);
					this->create_delete_job(this);
					return status;	
				}
				
				/* get the list of suggested proposals */ 
				status = sa_payload->create_proposal_substructure_iterator(sa_payload, &suggested_proposals, TRUE);
				if (status != SUCCESS)
				{	
					this->logger->log(this->logger, ERROR, "Fatal error: Could not create iterator on suggested proposals");
					accepted_proposals->destroy(accepted_proposals);
					payloads->destroy(payloads);
					this->create_delete_job(this);
					return status;
				}
				
				/* now let the configuration-manager select a subset of the proposals */
				status = global_configuration_manager->select_proposals_for_host(global_configuration_manager,
									this->other.host, suggested_proposals, accepted_proposals);
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, CONTROL | MORE, "No proposal of suggested proposals selected");
					suggested_proposals->destroy(suggested_proposals);
					accepted_proposals->destroy(accepted_proposals);
					payloads->destroy(payloads);
					this->create_delete_job(this);
					return status;
				}
				
				/* iterators are not needed anymore */			
				suggested_proposals->destroy(suggested_proposals);
				accepted_proposals->destroy(accepted_proposals);
				
				this->logger->log(this->logger, CONTROL | MORE, "SA Payload processed");
				/* ok, we have what we need for sa_payload (proposals are stored in this->proposals)*/
				break;
			}
			case KEY_EXCHANGE:
			{
				ke_payload_t *ke_payload = (ke_payload_t*)payload;
				diffie_hellman_group_t group;
				diffie_hellman_t *dh;
				bool allowed_group;
				
				group = ke_payload->get_dh_group_number(ke_payload);
				
				status = global_configuration_manager->is_dh_group_allowed_for_host(global_configuration_manager,
								this->other.host, group, &allowed_group);

				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR | MORE, "Could not get informations about DH group");
					payloads->destroy(payloads);
					this->create_delete_job(this);
					return status;
				}
				if (!allowed_group)
				{
					/** @todo Send info reply */	
				}
				
				/* create diffie hellman object to handle DH exchange */
				dh = diffie_hellman_create(group);
				if (dh == NULL)
				{
					this->logger->log(this->logger, ERROR, "Could not generate DH object");
					payloads->destroy(payloads);
					this->create_delete_job(this);
					return OUT_OF_RES;
				}

				this->logger->log(this->logger, CONTROL | MORE, "Set other DH public value");
				
				status = dh->set_other_public_value(dh, ke_payload->get_key_exchange_data(ke_payload));
				if (status != SUCCESS)
				{
					this->logger->log(this->logger, ERROR, "Could not set other DH public value");
					dh->destroy(dh);
					payloads->destroy(payloads);
					this->create_delete_job(this);
					return OUT_OF_RES;
				}

				if (this->ike_sa_init_data.diffie_hellman != NULL)
				{
					this->logger->log(this->logger, CONTROL | MORE, "Going to destroy allready existing diffie_hellman object");	
					this->ike_sa_init_data.diffie_hellman->destroy(this->ike_sa_init_data.diffie_hellman);
				}
				this->ike_sa_init_data.diffie_hellman = dh;
				
				this->logger->log(this->logger, CONTROL | MORE, "KE Payload processed");
				break;
			}
			case NONCE:
			{
				nonce_payload_t *nonce_payload = (nonce_payload_t*)payload;
				chunk_t nonce;

				this->logger->log(this->logger, CONTROL | MORE, "Get nonce value and store it");
				nonce_payload->get_nonce(nonce_payload, &nonce);
				/** @todo free if there is already one */
				this->ike_sa_init_data.received_nonce.ptr = allocator_clone_bytes(nonce.ptr, nonce.len);
				this->ike_sa_init_data.received_nonce.len = nonce.len;
				if (this->ike_sa_init_data.received_nonce.ptr == NULL)
				{
					payloads->destroy(payloads);
					this->create_delete_job(this);
					return OUT_OF_RES;
				}
				
				this->logger->log(this->logger, CONTROL | MORE, "Nonce Payload processed");
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR | MORE, "Payload type not supported!");
				payloads->destroy(payloads);
				this->create_delete_job(this);
				return OUT_OF_RES;				
			}
				
		}
			
	}
	/* iterator can be destroyed */
	payloads->destroy(payloads);
	
	this->logger->log(this->logger, CONTROL | MORE, "Request successfully handled. Going to create reply.");

	
	if (this->ike_sa_init_data.sent_nonce.ptr != NULL)
	{
		this->logger->log(this->logger, ERROR, "Nonce for IKE_SA_INIT phase already existing!");
		return FAILED;	
	}

	this->logger->log(this->logger, CONTROL | MOST, "Going to create nonce.");		
	if (this->randomizer->allocate_pseudo_random_bytes(this->randomizer, NONCE_SIZE, &(this->ike_sa_init_data.sent_nonce)) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not create nonce!");
		return OUT_OF_RES;
	}
		

	/* set up the reply */
	status = this->build_message(this, IKE_SA_INIT, FALSE, &response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not create empty message");
		this->create_delete_job(this);
		return status;	
	}
	
	/* build SA payload */		
	status = this->build_sa_payload(this, (sa_payload_t**)&payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not build SA payload");
		this->create_delete_job(this);
		response->destroy(response);
		return status;
	}
	
	this	->logger->log(this->logger, CONTROL|MOST, "add SA payload to message");
	status = response->add_payload(response, payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not add SA payload to message");
		this->create_delete_job(this);
		response->destroy(response);
		return status;
	}
	
	/* build KE payload */
	status = this->build_ke_payload(this,(ke_payload_t **) &payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not build KE payload");
		this->create_delete_job(this);
		response->destroy(response);
		return status;
	}

	this	->logger->log(this->logger, CONTROL|MOST, "add KE payload to message");
	status = response->add_payload(response, payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not add KE payload to message");
		this->create_delete_job(this);
		response->destroy(response);
		return status;
	}
	
	/* build Nonce payload */
	status = this->build_nonce_payload(this, (nonce_payload_t**)&payload);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not build NONCE payload");
		this->create_delete_job(this);
		response->destroy(response);
		return status;
	}

	this	->logger->log(this->logger, CONTROL|MOST, "add nonce payload to message");
	status = response->add_payload(response, payload);
	if (status != SUCCESS)
	{	
		this->logger->log(this->logger, ERROR, "Could not add nonce payload to message");
		this->create_delete_job(this);
		response->destroy(response);
		return status;
	}
	
	/* generate packet */	
	this	->logger->log(this->logger, CONTROL|MOST, "generate packet from message");
	status = response->generate(response, &packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: could not generate packet from message");
		this->create_delete_job(this);
		response->destroy(response);
		return status;
	}
	
	this	->logger->log(this->logger, CONTROL|MOST, "Add packet to global send queue");
	status = global_send_queue->add(global_send_queue, packet);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not add packet to send queue");
		this->create_delete_job(this);
		response->destroy(response);
		return status;
	}

	if (	this->last_responded_message != NULL)
	{
		/* destroy message */
		this	->logger->log(this->logger, CONTROL|MOST, "Destroy stored last responded message");
		this->last_responded_message->destroy(this->last_responded_message);
	}

	this->last_responded_message	 = response;

	/* state has NOW changed :-) */
	this	->logger->log(this->logger, CONTROL|MORE, "Change state of IKE_SA from %s to %s",mapping_find(ike_sa_state_m,this->state),mapping_find(ike_sa_state_m,IKE_SA_INIT_REQUESTED) );
	this->state = IKE_SA_INIT_RESPONDED;
	
	
	return SUCCESS;
}

static status_t transto_ike_auth_requested(private_ike_sa_t *this, message_t *response)
{	
	status_t status;
	linked_list_iterator_t *payloads;

	
	/* parse incoming message */
	status = response->parse_body(response);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Could not parse body");
		return status;	
	}
	/* iterate over incoming payloads */
	status = response->get_payload_iterator(response, &payloads);
	if (status != SUCCESS)
	{
		response->destroy(response);
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
				
				dh = this->ike_sa_init_data.diffie_hellman;

			
				status = dh->set_other_public_value(dh, ke_payload->get_key_exchange_data(ke_payload));
				if (status != SUCCESS)
				{
					dh->destroy(dh);
					payloads->destroy(payloads);
					return OUT_OF_RES;
				}
				
				status = dh->get_shared_secret(dh, &shared_secret);
				
				this->logger->log_chunk(this->logger, RAW, "Shared secret", &shared_secret);
				
				break;
			}
			case NONCE:
			{
				nonce_payload_t *nonce_payload = (nonce_payload_t*)payload;
				chunk_t nonce;
				
				nonce_payload->get_nonce(nonce_payload, &nonce);
				/** @todo free if there is already one */
				this->ike_sa_init_data.received_nonce.ptr = allocator_clone_bytes(nonce.ptr, nonce.len);
				this->ike_sa_init_data.received_nonce.len = nonce.len;
				if (this->ike_sa_init_data.received_nonce.ptr == NULL)
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
	
	printf("done.\n");

	/* set up the reply */
	status = this->build_message(this, IKE_SA_INIT, FALSE, &response);
	if (status != SUCCESS)
	{
		this->create_delete_job(this);
		return status;	
	}

	response->destroy(response);
	
	return SUCCESS;
	
	
}

/**
 * @brief implements function process_configuration of private_ike_sa_t
 */
static status_t initialize_connection(private_ike_sa_t *this, char *name)
{
	/* work is done in transto_ike_sa_init_requested */
	return (this->transto_ike_sa_init_requested(this,name));
}

/**
 * @brief implements function private_ike_sa_t.get_id
 */
static ike_sa_id_t* get_id(private_ike_sa_t *this)
{
	return this->ike_sa_id;
}

/**
 * implements private_ike_sa_t.build_sa_payload
 */
static status_t build_sa_payload(private_ike_sa_t *this, sa_payload_t **payload)
{
	sa_payload_t* sa_payload;
	linked_list_iterator_t *proposal_iterator;
	status_t status;
	
	
	/* SA payload takes proposals from this->ike_sa_init_data.proposals and writes them to the created sa_payload */

	this->logger->log(this->logger, CONTROL|MORE, "building sa payload");
	
	status = this->ike_sa_init_data.proposals->create_iterator(this->ike_sa_init_data.proposals, &proposal_iterator, FALSE);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: Could not create iterator on list for proposals");
		return status;	
	}
	
	sa_payload = sa_payload_create();
	if (sa_payload == NULL)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: Could not create SA payload object");
		return OUT_OF_RES;
	}
	
	while (proposal_iterator->has_next(proposal_iterator))
	{
		proposal_substructure_t *current_proposal;
		proposal_substructure_t *current_proposal_clone;
		status = proposal_iterator->current(proposal_iterator,(void **) &current_proposal);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, ERROR, "Could not get current proposal needed to copy");
			sa_payload->destroy(sa_payload);
			return status;	
		}
		status = current_proposal->clone(current_proposal,&current_proposal_clone);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, ERROR, "Could not clone current proposal");
			sa_payload->destroy(sa_payload);
			return status;	
		}
		
		status = sa_payload->add_proposal_substructure(sa_payload,current_proposal_clone);
		if (status != SUCCESS)
		{
			this->logger->log(this->logger, ERROR, "Could not add cloned proposal to SA payload");
			sa_payload->destroy(sa_payload);
			return status;	
		}

	}
	
	this->logger->log(this->logger, CONTROL|MORE, "sa payload buildet");
	
	*payload = sa_payload;
	
	return SUCCESS;
}

static status_t build_ke_payload(private_ike_sa_t *this, ke_payload_t **payload)
{
	ke_payload_t *ke_payload;
	chunk_t key_data;
	status_t status;

	this->logger->log(this->logger, CONTROL|MORE, "building ke payload");
	
	if (this->state != NO_STATE)
	{
		this->logger->log(this->logger, ERROR, "KE payload in state %s not supported",mapping_find(ike_sa_state_m,this->state));
		return FALSE;
	}
	
	switch(this->ike_sa_id->is_initiator(this->ike_sa_id))
	{
		case TRUE:
		case FALSE:
		{
			this	->logger->log(this->logger, CONTROL|MORE, "get public dh value to send in ke payload");
			status = this->ike_sa_init_data.diffie_hellman->get_my_public_value(this->ike_sa_init_data.diffie_hellman,&key_data);
			if (status != SUCCESS)
			{
				this->logger->log(this->logger, ERROR, "Could not get my DH public value");
				return status;
			}
		
			ke_payload = ke_payload_create();
			if (ke_payload == NULL)
			{
				this->logger->log(this->logger, ERROR, "Could not create KE payload");
				allocator_free_chunk(key_data);
				return OUT_OF_RES;	
			}
			ke_payload->set_dh_group_number(ke_payload, MODP_1024_BIT);
			if (ke_payload->set_key_exchange_data(ke_payload, key_data) != SUCCESS)
			{
				this->logger->log(this->logger, ERROR, "Could not set key exchange data of KE payload");
				ke_payload->destroy(ke_payload);
				allocator_free_chunk(key_data);
				return OUT_OF_RES;
			}
			allocator_free_chunk(key_data);
		
			*payload = ke_payload;
			return SUCCESS;			
		}
	}

	return FAILED;
}

/**
 * implements private_ike_sa_t.build_nonce_payload
 */
static status_t build_nonce_payload(private_ike_sa_t *this, nonce_payload_t **payload)
{
	nonce_payload_t *nonce_payload;
	status_t status;
	
	this->logger->log(this->logger, CONTROL|MORE, "building nonce payload");
	
	if (this->state != NO_STATE)
	{
		this->logger->log(this->logger, ERROR, "Nonce payload in state %s not supported",mapping_find(ike_sa_state_m,this->state));
		return FALSE;
	}

	nonce_payload = nonce_payload_create();
	if (nonce_payload == NULL)
	{	
		this->logger->log(this->logger, ERROR, "Fatal error: could not create nonce payload object");
		return OUT_OF_RES;	
	}

	status = nonce_payload->set_nonce(nonce_payload, this->ike_sa_init_data.sent_nonce);
	
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: could not set nonce data of payload");
		nonce_payload->destroy(nonce_payload);
		return status;
	}
		
	*payload = nonce_payload;
	
	return SUCCESS;
}

/**
 * @brief implements function resend_last_reply of private_ike_sa_t
 */
status_t resend_last_reply (private_ike_sa_t *this)
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

status_t create_delete_job (private_ike_sa_t *this)
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
 * @brief implements function destroy of private_ike_sa_t
 */
static status_t destroy (private_ike_sa_t *this)
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
	
	/* destroy stored proposal */
	this->logger->log(this->logger, CONTROL | MOST, "Destroy stored proposals");
	while (this->ike_sa_init_data.proposals->get_count(this->ike_sa_init_data.proposals) > 0)
	{
		proposal_substructure_t *current_proposal;
		this->ike_sa_init_data.proposals->remove_first(this->ike_sa_init_data.proposals,(void **)&current_proposal);
		current_proposal->destroy(current_proposal);
	}
	this->ike_sa_init_data.proposals->destroy(this->ike_sa_init_data.proposals);

	
	this->logger->log(this->logger, CONTROL | MOST, "Destroy randomizer");
	this->randomizer->destroy(this->randomizer);


	/* destroy ike_sa_init data */
	this->logger->log(this->logger, CONTROL | MOST, "Going to destroy ike_sa_init data");
	if (this->ike_sa_init_data.diffie_hellman != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy diffie hellman object");
		this->ike_sa_init_data.diffie_hellman->destroy(this->ike_sa_init_data.diffie_hellman);
	}
	if (this->ike_sa_init_data.sent_nonce.ptr != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy sent nonce data");
		allocator_free_chunk(this->ike_sa_init_data.sent_nonce);		
	}
	if (this->ike_sa_init_data.received_nonce.ptr != NULL)
	{
		this->logger->log(this->logger, CONTROL | MOST, "Destroy received nonce data");
		allocator_free_chunk(this->ike_sa_init_data.received_nonce);
	}
	
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
	private_ike_sa_t *this = allocator_alloc_thing(private_ike_sa_t);
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
	this->build_sa_payload = build_sa_payload;
	this->build_nonce_payload = build_nonce_payload;
	this->build_ke_payload = build_ke_payload;
	this->build_message = build_message;
	this->transto_ike_sa_init_requested = transto_ike_sa_init_requested;
	this->transto_ike_sa_init_responded = transto_ike_sa_init_responded;
	this->transto_ike_auth_requested = transto_ike_auth_requested;
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
	this->ike_sa_init_data.diffie_hellman = NULL;
	this->ike_sa_init_data.dh_group_number = 0;
	/* 1 means highest priority */
	this->ike_sa_init_data.dh_group_priority = 1;
	this->ike_sa_init_data.sent_nonce.len = 0;
	this->ike_sa_init_data.sent_nonce.ptr = NULL;
	this->ike_sa_init_data.received_nonce.len = 0;
	this->ike_sa_init_data.received_nonce.ptr = NULL;
	this->ike_sa_init_data.proposals = linked_list_create();
	if (this->ike_sa_init_data.proposals == NULL)
	{
		this->logger->log(this->logger, ERROR, "Fatal error: Could not create list for child_sa's");
		this->child_sas->destroy(this->child_sas);
		this->ike_sa_id->destroy(this->ike_sa_id);
		this->randomizer->destroy(this->randomizer);
		global_logger_manager->destroy_logger(global_logger_manager,this->logger);
		allocator_free(this);
	}
	this->last_requested_message = NULL;
	this->last_responded_message = NULL;
	this->message_id_out = 0;
	this->message_id_in = 0;


	/* at creation time, IKE_SA isn't in a specific state */
	this->state = NO_STATE;

	return (&this->public);
}
