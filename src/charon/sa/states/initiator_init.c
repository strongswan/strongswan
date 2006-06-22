/**
 * @file initiator_init.c
 * 
 * @brief Implementation of initiator_init_t.
 * 
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
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
 
#include "initiator_init.h"


#include <daemon.h>
#include <sa/states/state.h>
#include <sa/states/ike_sa_init_requested.h>
#include <queues/jobs/retransmit_request_job.h>
#include <crypto/diffie_hellman.h>
#include <crypto/hashers/hasher.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/nonce_payload.h>


typedef struct private_initiator_init_t private_initiator_init_t;

/**
 * Private data of a initiator_init_t object..
 *
 */
struct private_initiator_init_t {
	/**
	 * Methods of the state_t interface.
	 */
	initiator_init_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	protected_ike_sa_t *ike_sa;
	
	/**
	 * Diffie hellman object used to generate public DH value.
	 * This objet is passed to the next state of type IKE_SA_INIT_REQUESTED.
	 */
	diffie_hellman_t *diffie_hellman;
	
	/**
	 * Sent nonce.
	 * This nonce is passed to the next state of type IKE_SA_INIT_REQUESTED.
	 */
	chunk_t sent_nonce;

	/**
	 * Assigned logger.
	 * 
	 * Is logger of ike_sa!
	 */
	logger_t *logger;
	
	/**
	 * Builds the SA payload for this state.
	 * 
	 * @param this		calling object
	 * @param request	message_t object to add the SA payload
	 */
	void (*build_sa_payload) (private_initiator_init_t *this, message_t *request);

	/**
	 * Builds the KE payload for this state.
	 * 
	 * @param this		calling object
	 * @param request	message_t object to add the KE payload
	 */
	void (*build_ke_payload) (private_initiator_init_t *this, message_t *request);
	
	/**
	 * Builds the NONCE payload for this state.
	 * 
	 * @param this		calling object
	 * @param request	message_t object to add the NONCE payload
	 */
	status_t (*build_nonce_payload) (private_initiator_init_t *this,message_t *request);	
	/**
	 * Builds the NAT-T Notify(NAT_DETECTION_SOURCE_IP) and
	 * Notify(NAT_DETECTION_DESTINATION_IP) payloads for this state.
	 * 
	 * @param this		calling object
	 * @param request	message_t object to add the Notify payloads
	 */
	void (*build_natd_payload) (private_initiator_init_t *this, message_t *request, notify_message_type_t type, host_t *host);

	/**
	 * Builds the NAT-T Notify(NAT_DETECTION_SOURCE_IP) and
	 * Notify(NAT_DETECTION_DESTINATION_IP) payloads for this state.
	 * 
	 * @param this		calling object
	 * @param request	message_t object to add the Notify payloads
	 */
	void (*build_natd_payloads) (private_initiator_init_t *this, message_t *request);

	/**
	 * Destroy function called internally of this class after state change to state 
	 * IKE_SA_INIT_REQUESTED succeeded.
	 * 
	 * This destroy function does not destroy objects which were passed to the new state.
	 * 
	 * @param this		calling object
	 */
	void (*destroy_after_state_change) (private_initiator_init_t *this);
};

/**
 * Implementation of initiator_init_t.initiate_connection.
 */
static status_t initiate_connection (private_initiator_init_t *this, connection_t *connection)
{
	policy_t *policy;
	diffie_hellman_group_t dh_group;
	host_t *my_host, *other_host;
	identification_t *my_id, *other_id;
	char *name;
	
	name = connection->get_name(connection);
	this->ike_sa->set_connection(this->ike_sa, connection);
	
	/* get policy */
	policy = charon->policies->get_policy_by_name(charon->policies, name);
	if (policy == NULL)
	{
		this->logger->log(this->logger, ERROR | LEVEL1, 
						  "could not get a policy named '%s', aborting", name);
		return DESTROY_ME;
	}
	this->ike_sa->set_policy(this->ike_sa, policy);
	
	my_host = connection->get_my_host(connection);
	other_host = connection->get_other_host(connection);
	my_id = policy->get_my_id(policy);
	other_id = policy->get_other_id(policy);
	
	this->logger->log(this->logger, CONTROL, "initiating connection \"%s\": %s[%s]...%s[%s]",
					  name,
					  my_host->get_address(my_host),
					  my_id->get_string(my_id),
					  other_host->get_address(other_host),
					  other_id->get_string(other_id));
	
	/* we must guess now a DH group. For that we choose our most preferred group */
	dh_group = connection->get_dh_group(connection);
	
	/* next step is done in retry_initiate_connection */
	return this->public.retry_initiate_connection(&this->public, dh_group);
}

/**
 * Implementation of initiator_init_t.retry_initiate_connection.
 */
status_t retry_initiate_connection (private_initiator_init_t *this, diffie_hellman_group_t dh_group)
{
	ike_sa_init_requested_t *next_state;
	chunk_t ike_sa_init_request_data;
	connection_t *connection;
	ike_sa_id_t *ike_sa_id;
	message_t *message;
	status_t status;
	
	this->diffie_hellman = diffie_hellman_create(dh_group);
	if (this->diffie_hellman == NULL)
	{
		this->logger->log(this->logger, AUDIT, "DH group %s (%d) not supported, aborting",
						  mapping_find(diffie_hellman_group_m, dh_group), dh_group);
		return DESTROY_ME;
	}
	
	connection = this->ike_sa->get_connection(this->ike_sa);
	ike_sa_id = this->ike_sa->public.get_id(&(this->ike_sa->public));
	ike_sa_id->set_responder_spi(ike_sa_id,0);

	/* going to build message */
	this->logger->log(this->logger, CONTROL|LEVEL2, "going to build message");
	this->ike_sa->build_message(this->ike_sa, IKE_SA_INIT, TRUE, &message);
	
	/* build SA payload */
	this->build_sa_payload(this, message);
	/* build KE payload */
	this->build_ke_payload(this, message);
	/* build Nonce payload */
	status = this->build_nonce_payload(this, message);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR, "building nonce payload failed, aborting");
		message->destroy(message);
		return DESTROY_ME;
	}
	
	/* build Notify(NAT-D) payloads */
	this->build_natd_payloads(this, message);
	
	/* message can now be sent (must not be destroyed) */
	status = this->ike_sa->send_request(this->ike_sa, message);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, "unable to initiate connection, could not send message, aborting");
		message->destroy(message);
		return DESTROY_ME;
	}
	
	message = this->ike_sa->get_last_requested_message(this->ike_sa);
	
	ike_sa_init_request_data = message->get_packet_data(message);

	/* state can now be changed */
	this->logger->log(this->logger, CONTROL|LEVEL2, "create next state object");
	next_state = ike_sa_init_requested_create(this->ike_sa, this->diffie_hellman, this->sent_nonce,ike_sa_init_request_data);
	this->ike_sa->set_new_state(this->ike_sa,(state_t *) next_state);
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "destroy old state object");
	this->destroy_after_state_change(this);
	return SUCCESS;
}

/**
 * Implementation of private_initiator_init_t.build_sa_payload.
 */
static void build_sa_payload(private_initiator_init_t *this, message_t *request)
{
	sa_payload_t* sa_payload;
	linked_list_t *proposal_list;
	connection_t *connection;
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "building SA payload");
	
	connection = this->ike_sa->get_connection(this->ike_sa);

	proposal_list = connection->get_proposals(connection);
	
	sa_payload = sa_payload_create_from_proposal_list(proposal_list);	

	this->logger->log(this->logger, CONTROL|LEVEL2, "add SA payload to message");
	request->add_payload(request, (payload_t *) sa_payload);
}

/**
 * Implementation of private_initiator_init_t.build_ke_payload.
 */
static void build_ke_payload(private_initiator_init_t *this, message_t *request)
{
	ke_payload_t *ke_payload;
	chunk_t key_data;
	diffie_hellman_group_t dh_group;
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "building KE payload");
	
	this->diffie_hellman->get_my_public_value(this->diffie_hellman, &key_data);
	dh_group = this->diffie_hellman->get_dh_group(this->diffie_hellman);

	ke_payload = ke_payload_create();
	ke_payload->set_dh_group_number(ke_payload, dh_group);
	ke_payload->set_key_exchange_data(ke_payload, key_data);
	
	chunk_free(&key_data);
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "add KE payload to message");
	request->add_payload(request, (payload_t *) ke_payload);
}

/**
 * Implementation of private_initiator_init_t.build_nonce_payload.
 */
static status_t build_nonce_payload(private_initiator_init_t *this, message_t *request)
{
	nonce_payload_t *nonce_payload;
	randomizer_t *randomizer;
	status_t status;
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "building NONCE payload");
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "get pseudo random bytes for NONCE");
	randomizer = this->ike_sa->get_randomizer(this->ike_sa);
	
	status = randomizer->allocate_pseudo_random_bytes(randomizer, NONCE_SIZE, &(this->sent_nonce));
	if (status != SUCCESS)
	{
		return status;
	}

	this->logger->log(this->logger, RAW|LEVEL2, "initiator NONCE",&(this->sent_nonce));
	
	nonce_payload = nonce_payload_create();
	
	nonce_payload->set_nonce(nonce_payload, this->sent_nonce);
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "add NONCE payload to message");
	request->add_payload(request, (payload_t *) nonce_payload);
	return SUCCESS;
}

/**
 * Implementation of private_initiator_init_t.build_natd_payload.
 */
static void build_natd_payload(private_initiator_init_t *this, message_t *request, notify_message_type_t type, host_t *host)
{
	chunk_t hash;
	this->logger->log(this->logger, CONTROL|LEVEL1, "Building Notify(NAT-D) payload");
	notify_payload_t *notify_payload;
	notify_payload = notify_payload_create();
	/*notify_payload->set_protocol_id(notify_payload, NULL);*/
	/*notify_payload->set_spi(notify_payload, NULL);*/
	notify_payload->set_notify_message_type(notify_payload, type);
	hash = this->ike_sa->generate_natd_hash(this->ike_sa,
			request->get_initiator_spi(request),
			request->get_responder_spi(request),
			host);
	notify_payload->set_notification_data(notify_payload, hash);
	chunk_free(&hash);
	this->logger->log(this->logger, CONTROL|LEVEL2, "Add Notify(NAT-D) payload to message");
	request->add_payload(request, (payload_t *) notify_payload);
}

/**
 * Implementation of private_initiator_init_t.build_natd_payloads.
 */
static void build_natd_payloads(private_initiator_init_t *this, message_t *request)
{
	connection_t	*connection;
	linked_list_t	*hostlist;
	iterator_t		*hostiter;
	host_t			*host;

	/*
	 * N(NAT_DETECTION_SOURCE_IP)+
	 */
	hostlist = charon->interfaces->get_addresses(charon->interfaces);
	hostiter = hostlist->create_iterator(hostlist, TRUE);
	while(hostiter->iterate(hostiter, (void**)&host)) {
		this->build_natd_payload(this, request, NAT_DETECTION_SOURCE_IP,
			host);
	}
	hostiter->destroy(hostiter);

	/*
	 * N(NAT_DETECTION_DESTINATION_IP)
	 */
	connection = this->ike_sa->get_connection(this->ike_sa);
	this->build_natd_payload(this, request, NAT_DETECTION_DESTINATION_IP,
			connection->get_other_host(connection));
}

/**
 * Implementation of state_t.process_message.
 */
static status_t process_message(private_initiator_init_t *this, message_t *message)
{
	this->logger->log(this->logger, ERROR, "in state INITIATOR_INIT, no message is processed");
	return FAILED;
}

/**
 * Implementation of state_t.get_state.
 */
static ike_sa_state_t get_state(private_initiator_init_t *this)
{
	return INITIATOR_INIT;
}

/**
 * Implementation of state_t.destroy.
 */
static void destroy(private_initiator_init_t *this)
{
	this->logger->log(this->logger, CONTROL | LEVEL3, "going to destroy initiator_init_t state object");

	/* destroy diffie hellman object */
	if (this->diffie_hellman != NULL)
	{
		this->diffie_hellman->destroy(this->diffie_hellman);
	}
	if (this->sent_nonce.ptr != NULL)
	{
		free(this->sent_nonce.ptr);
	}
	free(this);
}

/**
 * Implementation of private_initiator_init_t.destroy_after_state_change
 */
static void destroy_after_state_change (private_initiator_init_t *this)
{
	this->logger->log(this->logger, CONTROL | LEVEL3, "going to destroy initiator_init_t state object");
	free(this);
}

/* 
 * Described in header.
 */
initiator_init_t *initiator_init_create(protected_ike_sa_t *ike_sa)
{
	private_initiator_init_t *this = malloc_thing(private_initiator_init_t);

	/* interface functions */
	this->public.state_interface.process_message = (status_t (*) (state_t *,message_t *)) process_message;
	this->public.state_interface.get_state = (ike_sa_state_t (*) (state_t *)) get_state;
	this->public.state_interface.destroy  = (void (*) (state_t *)) destroy;
	
	/* public functions */
	this->public.initiate_connection = (status_t (*)(initiator_init_t *, connection_t*)) initiate_connection;
	this->public.retry_initiate_connection = (status_t (*)(initiator_init_t *, int )) retry_initiate_connection;
	
	/* private functions */
	this->destroy_after_state_change = destroy_after_state_change;
	this->build_nonce_payload = build_nonce_payload;
	this->build_sa_payload = build_sa_payload;
	this->build_ke_payload = build_ke_payload;
	this->build_natd_payload = build_natd_payload;
	this->build_natd_payloads = build_natd_payloads;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);
	this->sent_nonce = CHUNK_INITIALIZER;
	this->diffie_hellman = NULL;

	return &(this->public);
}
