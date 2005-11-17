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
#include "utils/allocator.h"
#include "utils/linked_list.h"
#include "utils/logger_manager.h"
#include "utils/randomizer.h"
#include "payloads/sa_payload.h"
#include "payloads/nonce_payload.h"
#include "payloads/ke_payload.h"
#include "payloads/transform_substructure.h"
#include "payloads/transform_attribute.h"


/**
 * States in which a IKE_SA can actually be
 */
typedef enum ike_sa_state_e ike_sa_state_t;

enum ike_sa_state_e {

	/**
	 * IKE_SA is is not in a state
	 */
	NO_STATE,

	/**
	 * A IKE_SA_INIT-message was sent: role initiator
	 */
	IKE_SA_INIT_REQUESTED,

	/**
	 * A IKE_SA_INIT-message was replied: role responder
	 */
	IKE_SA_INIT_RESPONDED,

	/**
	 * An IKE_AUTH-message was sent after a successful
	 * IKE_SA_INIT-exchange: role initiator
	 */
	IKE_AUTH_REQUESTED,

	/**
	 * An IKE_AUTH-message was replied: role responder.
	 * In this state, all the informations for an IKE_SA
	 * and one CHILD_SA are known.
	 */
	IKE_SA_INITIALIZED
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
	
	status_t (*build_sa_payload) (private_ike_sa_t *this, sa_payload_t **payload);
	status_t (*build_nonce_payload) (private_ike_sa_t *this, nonce_payload_t **payload);
	status_t (*build_ke_payload) (private_ike_sa_t *this, ke_payload_t **payload);

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
	ike_sa_state_t current_state;
	
	/**
	 * is this IKE_SA the original initiator of this IKE_SA
	 */
	bool original_initiator;
	
	/**
	 * this SA's source for random data
	 */
	randomizer_t *randomizer;
	
	linked_list_t *sent_messages;	
	
	struct {
		host_t *host;
	} me;
	
	struct {
		host_t *host;
	} other;
	
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
	status_t status;
	/* @TODO Add Message Processing here */
	
	this->logger->log(this->logger, CONTROL_MORE, "Process message ...");
	
	//this->logger->log(this->logger, CONTROL_MORE, "First Payload type %s",mapping_find(payload_type_m,message->get_next_payload(message)));
	
	status = message->parse_body(message);
	
	
	/*
			iterator->current(iterator, (void**)&next_payload);
		payload->set_next_type(payload, next_payload->get_type(next_payload));
		status = generator->generate_payload(generator, payload);
		if (status != SUCCESS)
		{
			generator->destroy(generator);
			ike_header->destroy(ike_header);
			return status;
		}
		payload = next_payload;
	}*/
	
	
	return status;
}

/**
 * @brief implements function process_configuration of private_ike_sa_t
 */
static status_t initialize_connection(private_ike_sa_t *this, char *name)
{
	message_t *message;
	payload_t *payload;
	packet_t *packet;
	status_t status;
	
	this->logger->log(this->logger, CONTROL, "initializing connection");
	
	this->original_initiator = TRUE;
	
	message = message_create();
	
	if (message == NULL)
	{
		return OUT_OF_RES;	
	}
	

	message->set_exchange_type(message, IKE_SA_INIT);
	message->set_original_initiator(message, this->original_initiator);
	message->set_message_id(message, 0);
	message->set_ike_sa_id(message, this->ike_sa_id);
	message->set_request(message, TRUE);
	
	status = this->build_sa_payload(this, (sa_payload_t**)&payload);
	if (status != SUCCESS)
	{
		message->destroy(message);
		return status;
	}
	payload->set_next_type(payload, KEY_EXCHANGE);
	message->add_payload(message, payload);
	
	status = this->build_ke_payload(this, (ke_payload_t**)&payload);
	if (status != SUCCESS)
	{
		message->destroy(message);
		return status;
	}
	payload->set_next_type(payload, NONCE);
	message->add_payload(message, payload);
	
	status = this->build_nonce_payload(this, (nonce_payload_t**)&payload);
	if (status != SUCCESS)
	{
		message->destroy(message);
		return status;
	}
	payload->set_next_type(payload, NO_PAYLOAD);
	message->add_payload(message, payload);
	
	status = message->generate(message, &packet);
	if (status != SUCCESS)
	{
		message->destroy(message);
		return status;
	}
	
	global_send_queue->add(global_send_queue, packet);


	message->destroy(message);


	return OUT_OF_RES;
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
	sa_payload_t *sa_payload;
	proposal_substructure_t *proposal;
	transform_substructure_t *transform;
	transform_attribute_t *attribute;
	
	
	this->logger->log(this->logger, CONTROL_MORE, "building sa payload");
	
	sa_payload = sa_payload_create();
	if (sa_payload == NULL)
	{
		return OUT_OF_RES;
	}
	
	do
	{	/* no loop, just to break */
		proposal = proposal_substructure_create();
		if (proposal == NULL)
		{
			break;
		}
		sa_payload->add_proposal_substructure(sa_payload, proposal);
		
		/* 
		 * Encryption Algorithm 
		 */
		transform = transform_substructure_create();
		if (transform == NULL)
		{
			break;
		}
		proposal->add_transform_substructure(proposal, transform);
		transform->set_is_last_transform(transform, FALSE);
		transform->set_transform_type(transform, ENCRYPTION_ALGORITHM);
		transform->set_transform_id(transform, ENCR_AES_CBC);
		
		attribute = transform_attribute_create();
		if (attribute == NULL)
		{		
			break;
		}
		transform->add_transform_attribute(transform, attribute);
		attribute->set_attribute_type(attribute, KEY_LENGTH);
		attribute->set_value(attribute, 16);
		
	 	/* 
	 	 * Pseudo-random Function
	 	 */
	 	transform = transform_substructure_create();
		if (transform == NULL)
		{
			break;
		}
		proposal->add_transform_substructure(proposal, transform);
		transform->set_is_last_transform(transform, FALSE);
		transform->set_transform_type(transform, PSEUDO_RANDOM_FUNCTION);
		transform->set_transform_id(transform, PRF_HMAC_SHA1);
		
		attribute = transform_attribute_create();
		if (attribute == NULL)
		{		
			break;
		}
		transform->add_transform_attribute(transform, attribute);
		attribute->set_attribute_type(attribute, KEY_LENGTH);
		attribute->set_value(attribute, 16);

	 	
	 	/* 
	 	 * Integrity Algorithm 
	 	 */
	 	transform = transform_substructure_create();
		if (transform == NULL)
		{
			break;
		}
		proposal->add_transform_substructure(proposal, transform);
		transform->set_is_last_transform(transform, FALSE);
		transform->set_transform_type(transform, INTEGRITIY_ALGORITHM);
		transform->set_transform_id(transform, AUTH_HMAC_SHA1_96);
		
		attribute = transform_attribute_create();
		if (attribute == NULL)
		{		
			break;
		}
		transform->add_transform_attribute(transform, attribute);
		attribute->set_attribute_type(attribute, KEY_LENGTH);
		attribute->set_value(attribute, 16);
	 	
	 	
	    /* 
	     * Diffie-Hellman Group 
	     */
	 	transform = transform_substructure_create();
		if (transform == NULL)
		{
			break;
		}
		proposal->add_transform_substructure(proposal, transform);
		transform->set_is_last_transform(transform, FALSE);
		transform->set_transform_type(transform, DIFFIE_HELLMAN_GROUP);
		transform->set_transform_id(transform, MODP_1024_BIT);
		
		*payload = sa_payload;
		
		return SUCCESS;
		
	} while(FALSE);
	
	return OUT_OF_RES;
}

/**
 * implements private_ike_sa_t.build_ke_payload
 */
static status_t build_ke_payload(private_ike_sa_t *this, ke_payload_t **payload)
{
	ke_payload_t *ke_payload;
	chunk_t key_data;
	
	
	this->logger->log(this->logger, CONTROL_MORE, "building ke payload");
	
	key_data.ptr = "12345";
	key_data.len = strlen("12345");
	
	
	ke_payload = ke_payload_create();
	if (ke_payload == NULL)
	{
		return OUT_OF_RES;	
	}
	ke_payload->set_dh_group_number(ke_payload, MODP_1024_BIT);
	if (ke_payload->set_key_exchange_data(ke_payload, key_data) != SUCCESS)
	{
		ke_payload->destroy(ke_payload);
		return OUT_OF_RES;
	}
	*payload = ke_payload;
	return SUCCESS;
}

/**
 * implements private_ike_sa_t.build_nonce_payload
 */
static status_t build_nonce_payload(private_ike_sa_t *this, nonce_payload_t **payload)
{
	nonce_payload_t *nonce_payload;
	chunk_t nonce;
	
	this->logger->log(this->logger, CONTROL_MORE, "building nonce payload");
	
	if (this->randomizer->allocate_pseudo_random_bytes(this->randomizer, 16, &nonce) != SUCCESS)
	{
		return OUT_OF_RES;
	}
	
	nonce_payload = nonce_payload_create();
	if (nonce_payload == NULL)
	{
		return OUT_OF_RES;	
	}
	
	nonce_payload->set_nonce(nonce_payload, nonce);
	
	*payload = nonce_payload;
	
	return SUCCESS;
}

/**
 * @brief implements function destroy of private_ike_sa_t
 */
static status_t destroy (private_ike_sa_t *this)
{
	linked_list_iterator_t *iterator;

	this->child_sas->create_iterator(this->child_sas, &iterator, TRUE);
	while (iterator->has_next(iterator))
	{
		payload_t *payload;
		iterator->current(iterator, (void**)&payload);
		payload->destroy(payload);
	}
	iterator->destroy(iterator);
	this->child_sas->destroy(this->child_sas);
	
	this->ike_sa_id->destroy(this->ike_sa_id);
	
	this->randomizer->destroy(this->randomizer);
	
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
	
	this->build_sa_payload = build_sa_payload;
	this->build_ke_payload = build_ke_payload;
	this->build_nonce_payload = build_nonce_payload;



	/* initialize private fields */
	if (ike_sa_id->clone(ike_sa_id,&(this->ike_sa_id)) != SUCCESS)
	{
		allocator_free(this);
		return NULL;
	}
	this->child_sas = linked_list_create();
	if (this->child_sas == NULL)
	{
		this->ike_sa_id->destroy(this->ike_sa_id);
		allocator_free(this);
		return NULL;
	}
	this->randomizer = randomizer_create();
	if (this->randomizer == NULL)
	{
		this->child_sas->destroy(this->child_sas);
		this->ike_sa_id->destroy(this->ike_sa_id);
		allocator_free(this);
	}
	this->sent_messages = linked_list_create();
	if (this->sent_messages == NULL)
	{
		this->randomizer->destroy(this->randomizer);
		this->child_sas->destroy(this->child_sas);
		this->ike_sa_id->destroy(this->ike_sa_id);
		allocator_free(this);
	}
	this->logger = global_logger_manager->create_logger(global_logger_manager, IKE_SA, NULL);
	if (this->logger ==  NULL)
	{
		this->randomizer->destroy(this->randomizer);
		this->child_sas->destroy(this->child_sas);
		this->ike_sa_id->destroy(this->ike_sa_id);
		this->sent_messages->destroy(this->sent_messages);
		allocator_free(this);
	}
	
	this->me.host = NULL;
	this->other.host = NULL;


	/* at creation time, IKE_SA isn't in a specific state */
	this->current_state = NO_STATE;

	return (&this->public);
}
