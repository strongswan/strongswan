/**
 * @file ike_sa_init.c
 *
 * @brief Implementation of ike_sa_init_t transaction.
 *
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include "ike_sa_init.h"

#include <string.h>

#include <daemon.h>
#include <crypto/diffie_hellman.h>
#include <crypto/hashers/hasher.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <sa/transactions/ike_auth.h>
#include <queues/jobs/delete_ike_sa_job.h>
#include <queues/jobs/rekey_ike_sa_job.h>


typedef struct private_ike_sa_init_t private_ike_sa_init_t;

/**
 * Private members of a ike_sa_init_t object..
 */
struct private_ike_sa_init_t {
	
	/**
	 * Public methods and transaction_t interface.
	 */
	ike_sa_init_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Message sent by our peer, if already generated
	 */
	message_t *message;
	
	/**
	 * Message ID this transaction uses
	 */
	u_int32_t message_id;
	
	/**
	 * Times we did send the request
	 */
	u_int32_t requested;
	
	/**
	 * Next transaction followed to this one. May be IKE_AUTH,
	 * or a IKE_SA_INIT retry
	 */
	transaction_t **next;
		
	/**
	 * Diffie hellman object used to generate public DH value.
	 */
	diffie_hellman_t *diffie_hellman;
	
	/**
	 * initiator chosen nonce
	 */
	chunk_t nonce_i;
	
	/**
	 * responder chosen nonce
	 */
	chunk_t nonce_r;
	
	/**
	 * connection definition used for initiation
	 */
	connection_t *connection;
	
	/**
	 * policy definition forwarded to ike_auth transaction
	 */
	policy_t *policy;
	
	/**
	 * Negotiated proposal used for IKE_SA
	 */
	proposal_t *proposal;
	
	/**
	 * Reqid to pass to IKE_AUTH, used for created CHILD_SA
	 */
	u_int32_t reqid;
	
	/**
	 * Unique ID for to enumerate all IKE_SAs in its name
	 */
	u_int32_t unique_id;
	
	/**
	 * Randomizer to generate nonces
	 */
	randomizer_t *randomizer;
	
	/**
	 * Hasher used to build NAT detection hashes
	 */
	hasher_t *nat_hasher;
	
	/**
	 * Precomputed NAT hash for source address
	 */
	chunk_t natd_src_hash;
	
	/**
	 * Precomputed NAT hash for destination address
	 */
	chunk_t natd_dst_hash;
	
	/**
	 * Did we process any NAT detection notifys for a source address?
	 */
	bool natd_src_seen;
	
	/**
	 * Did we process any NAT detection notifys for a destination address?
	 */
	bool natd_dst_seen;
	
	/**
	 * Have we found a matching source address NAT hash?
	 */
	bool natd_src_matched;
	
	/**
	 * Have we found a matching destination address NAT hash?
	 */
	bool natd_dst_matched;
	
	/**
	 * Assigned logger.
	 */
	logger_t *logger;
};

/**
 * Implementation of ike_sa_init_t.use_dh_group.
 */
static bool use_dh_group(private_ike_sa_init_t *this, diffie_hellman_group_t dh_group)
{
	if (this->connection->check_dh_group(this->connection, dh_group))
	{
		this->diffie_hellman = diffie_hellman_create(dh_group);
		if (this->diffie_hellman)
		{
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Implementation of ike_sa_init_t.set_config.
 */
static void set_config(private_ike_sa_init_t *this,
					   connection_t *connection, policy_t *policy)
{
	this->connection = connection;
	this->policy = policy;
}

/**
 * Implementation of ike_sa_init_t.set_reqid.
 */
static void set_reqid(private_ike_sa_init_t *this, u_int32_t reqid)
{
	this->reqid = reqid;
}

/**
 * Implementation of transaction_t.get_message_id.
 */
static u_int32_t get_message_id(private_ike_sa_init_t *this)
{
	return this->message_id;
}

/**
 * Implementation of transaction_t.requested.
 */
static u_int32_t requested(private_ike_sa_init_t *this)
{
	return this->requested++;
}

/**
 * Build NAT detection hash for a host
 */
static chunk_t generate_natd_hash(private_ike_sa_init_t *this,
								  ike_sa_id_t * ike_sa_id, host_t *host)
{
	chunk_t natd_chunk, spi_i_chunk, spi_r_chunk, addr_chunk, port_chunk;
	chunk_t natd_hash;
	u_int64_t spi_i, spi_r;
	u_int16_t port;
	
	/* prepare all requred chunks */
	spi_i = ike_sa_id->get_initiator_spi(ike_sa_id);
	spi_r = ike_sa_id->get_responder_spi(ike_sa_id);
	spi_i_chunk.ptr = (void*)&spi_i;
	spi_i_chunk.len = sizeof(spi_i);
	spi_r_chunk.ptr = (void*)&spi_r;
	spi_r_chunk.len = sizeof(spi_r);
	port = htons(host->get_port(host));
	port_chunk.ptr = (void*)&port;
	port_chunk.len = sizeof(port);
	addr_chunk = host->get_address(host);
	
	/*  natd_hash = SHA1( spi_i | spi_r | address | port ) */
	natd_chunk = chunk_cat("cccc", spi_i_chunk, spi_r_chunk, addr_chunk, port_chunk);
	this->nat_hasher->allocate_hash(this->nat_hasher, natd_chunk, &natd_hash);
	this->logger->log_chunk(this->logger, RAW, "natd_chunk", natd_chunk);
	this->logger->log_chunk(this->logger, RAW, "natd_hash", natd_hash);
	
	chunk_free(&natd_chunk);
	return natd_hash;
}

/**
 * Build a NAT detection notify payload.
 */
static notify_payload_t *build_natd_payload(private_ike_sa_init_t *this,
											notify_type_t type, host_t *host)
{
	chunk_t hash;
	notify_payload_t *notify;	
	ike_sa_id_t *ike_sa_id;	
	
	ike_sa_id = this->ike_sa->get_id(this->ike_sa);
	notify = notify_payload_create();
	notify->set_notify_type(notify, type);
	hash = generate_natd_hash(this, ike_sa_id, host);
	notify->set_notification_data(notify, hash);
	chunk_free(&hash);
	
	return notify;
}

/**
 * destroy a list of proposals
 */
static void destroy_proposal_list(linked_list_t *list)
{
	proposal_t *proposal;
	
	while (list->remove_last(list, (void**)&proposal) == SUCCESS)
	{
		proposal->destroy(proposal);
	}
	list->destroy(list);
}

/**
 * Implementation of transaction_t.get_request.
 */
static status_t get_request(private_ike_sa_init_t *this, message_t **result)
{
	message_t *request;
	host_t *me, *other;
	identification_t *my_id, *other_id;
	char name[64];
	
	/* check if we already have built a message (retransmission) */
	if (this->message)
	{
		*result = this->message;
		return SUCCESS;
	}
	
	me = this->connection->get_my_host(this->connection);
	other = this->connection->get_other_host(this->connection);
	
	/* we already set up the IDs. Mine is already fully qualified, other
	* will be updated in the ike_auth transaction */
	my_id = this->policy->get_my_id(this->policy);
	other_id = this->policy->get_other_id(this->policy);
	this->ike_sa->set_my_id(this->ike_sa, my_id->clone(my_id));
	this->ike_sa->set_other_id(this->ike_sa, other_id->clone(other_id));
	if (snprintf(name, sizeof(name), "%s{%d}",
				 this->connection->get_name(this->connection),
				 this->unique_id) > 0)
	{
		this->ike_sa->set_name(this->ike_sa, name);
	}
	
	/* build the request */
	request = message_create();
	request->set_source(request, me->clone(me));
	request->set_destination(request, other->clone(other));
	request->set_exchange_type(request, IKE_SA_INIT);
	request->set_request(request, TRUE);
	request->set_message_id(request, this->message_id);
	request->set_ike_sa_id(request, this->ike_sa->get_id(this->ike_sa));
	/* apply for caller */
	*result = request;
	/* store for retransmission */
	this->message = request;
	
	/* if the DH group is set via use_dh_group(), we already have a DH object */
	if (!this->diffie_hellman)
	{
		diffie_hellman_group_t dh_group;
		
		dh_group = this->connection->get_dh_group(this->connection);
		this->diffie_hellman = diffie_hellman_create(dh_group);
		if (this->diffie_hellman == NULL)
		{
			this->logger->log(this->logger, AUDIT,
							  "DH group %s (%d) not supported, aborting",
							  mapping_find(diffie_hellman_group_m, dh_group), dh_group);
			return DESTROY_ME;
		}
	}
	
	{	/* build the SA payload from proposals */
		sa_payload_t *sa_payload;
		linked_list_t *proposal_list;
		
		proposal_list = this->connection->get_proposals(this->connection);
		sa_payload = sa_payload_create_from_proposal_list(proposal_list);
		destroy_proposal_list(proposal_list);
		
		request->add_payload(request, (payload_t*)sa_payload);
	}
	
	{	/* build the KE payload from the DH object */
		ke_payload_t *ke_payload;
		
		ke_payload = ke_payload_create_from_diffie_hellman(this->diffie_hellman);
		
		request->add_payload(request, (payload_t*)ke_payload);
	}
	
	{	/* build the NONCE payload for us (initiator) */
		nonce_payload_t *nonce_payload;
		
		if (this->randomizer->allocate_pseudo_random_bytes(this->randomizer, 
			NONCE_SIZE, &this->nonce_i) != SUCCESS)
		{
			return DESTROY_ME;
		}
		nonce_payload = nonce_payload_create();
		nonce_payload->set_nonce(nonce_payload, this->nonce_i);
		
		request->add_payload(request, (payload_t*)nonce_payload);
	}
	
	{	/* build NAT_DETECTION notifys */
		notify_payload_t *notify;
		linked_list_t *list;
		host_t *host;
		
		/* N(NAT_DETECTION_SOURCE_IP)+ */
		list = charon->socket->create_local_address_list(charon->socket);
		while (list->remove_first(list, (void**)&host) == SUCCESS)
		{
			/* TODO: should we only include NAT payloads for addresses
			 * of used address family? */
			notify = build_natd_payload(this, NAT_DETECTION_SOURCE_IP, host);
			host->destroy(host);
			request->add_payload(request, (payload_t*)notify);
		}
		list->destroy(list);
		
		/* N(NAT_DETECTION_DESTINATION_IP) */
		notify = build_natd_payload(this, NAT_DETECTION_DESTINATION_IP, other);
		request->add_payload(request, (payload_t*)notify);
	}
	
	this->ike_sa->set_state(this->ike_sa, IKE_CONNECTING);
	return SUCCESS;
}

/**
 * Handle all kind of notifys
 */
static status_t process_notifys(private_ike_sa_init_t *this, notify_payload_t *notify_payload)
{
	chunk_t notification_data;
	notify_type_t notify_type = notify_payload->get_notify_type(notify_payload);
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "process notify type %s",
					  mapping_find(notify_type_m, notify_type));

	switch (notify_type)
	{
		case NO_PROPOSAL_CHOSEN:
		{
			this->logger->log(this->logger, AUDIT, 
							  "received a NO_PROPOSAL_CHOSEN notify, deleting IKE_SA");
			return DESTROY_ME;
		}
		case INVALID_MAJOR_VERSION:
		{
			this->logger->log(this->logger, AUDIT, 
							  "received a INVALID_MAJOR_VERSION notify, deleting IKE_SA");
			return DESTROY_ME;
		}
		case INVALID_KE_PAYLOAD:
		{
			chunk_t notify_data;
			diffie_hellman_group_t dh_group, old_dh_group;
			ike_sa_init_t *retry;
			
			old_dh_group = this->connection->get_dh_group(this->connection);
			notify_data = notify_payload->get_notification_data(notify_payload);
			dh_group = ntohs(*((u_int16_t*)notify_data.ptr));
			
			this->logger->log(this->logger, AUDIT, 
							  "peer didn't accept DH group %s, it requested %s",
							  mapping_find(diffie_hellman_group_m, old_dh_group),
							  mapping_find(diffie_hellman_group_m, dh_group));
			if (!this->connection->check_dh_group(this->connection, dh_group))
			{
				this->logger->log(this->logger, AUDIT, 
								  "requested DH group not acceptable, aborting");
				return DESTROY_ME;
			}
			retry = ike_sa_init_create(this->ike_sa);
			retry->set_config(retry, this->connection, this->policy);
			this->connection = NULL;
			this->policy = NULL;
			retry->use_dh_group(retry, dh_group);
			*this->next = (transaction_t*)retry;
			return FAILED;
		}
		case NAT_DETECTION_DESTINATION_IP:
		{
			this->natd_dst_seen = TRUE;
			if (this->natd_dst_matched)
			{
				return SUCCESS;
			}
			notification_data = notify_payload->get_notification_data(notify_payload);
			if (chunk_equals(notification_data, this->natd_dst_hash))
			{
				this->natd_dst_matched = TRUE;
				this->logger->log(this->logger, CONTROL|LEVEL3, "NAT-D dst hash match");
			}
			else
			{
				this->logger->log(this->logger, CONTROL|LEVEL3, "NAT-D dst hash mismatch");
			}
			return SUCCESS;
		}
		case NAT_DETECTION_SOURCE_IP:
		{
			this->natd_src_seen = TRUE;;
			if (this->natd_src_matched)
			{
				return SUCCESS;
			}
			notification_data = notify_payload->get_notification_data(notify_payload);
			if (chunk_equals(notification_data, this->natd_src_hash))
			{
				this->natd_src_matched = TRUE;
				this->logger->log(this->logger, CONTROL|LEVEL3, "NAT-D src hash match");
			}
			else
			{
				this->logger->log(this->logger, CONTROL|LEVEL3, "NAT-D src hash mismatch");
			}
			return SUCCESS;
		}
		default:
		{
			if (notify_type < 16383)
			{
				this->logger->log(this->logger, AUDIT, 
								  "received %s notify error (%d), deleting IKE_SA",
								  mapping_find(notify_type_m, notify_type),
								  notify_type);
				return DESTROY_ME;	
			}
			else
			{
				this->logger->log(this->logger, CONTROL, 
								  "received %s notify (%d), ignored",
								  mapping_find(notify_type_m, notify_type),
								  notify_type);
				return SUCCESS;
			}
		}
	}
}

/**
 * Implementation of transaction_t.get_response.
 */
static status_t get_response(private_ike_sa_init_t *this, 
							 message_t *request, message_t **result,
							 transaction_t **next)
{
	host_t *me, *other;
	message_t *response;
	status_t status;
	iterator_t *payloads;
	sa_payload_t *sa_request = NULL;
	ke_payload_t *ke_request = NULL;
	nonce_payload_t *nonce_request = NULL;
	ike_sa_id_t *ike_sa_id;
	u_int32_t timeout;
	char name[64];
	
	/* check if we already have built a response (retransmission) */
	if (this->message)
	{
		*result = this->message;
		return SUCCESS;
	}
	
	me = request->get_destination(request);
	other = request->get_source(request);
	this->message_id = request->get_message_id(request);
	
	/* set up response */
	response = message_create();
	response->set_source(response, me->clone(me));
	response->set_destination(response, other->clone(other));
	response->set_exchange_type(response, IKE_SA_INIT);
	response->set_request(response, FALSE);
	response->set_message_id(response, this->message_id);
	response->set_ike_sa_id(response, this->ike_sa->get_id(this->ike_sa));
	this->message = response;
	*result = response;
	
	/* check message type */
	if (request->get_exchange_type(request) != IKE_SA_INIT)
	{
		this->logger->log(this->logger, ERROR, 
						  "IKE_SA_INIT request of invalid type, deleting IKE_SA");
		return DESTROY_ME;
	}
	
	/* this is the first message to process, find a connection for IKE_SA */
	this->connection = charon->connections->get_connection_by_hosts(
			charon->connections, me, other);
	if (this->connection == NULL)
	{
		notify_payload_t *notify = notify_payload_create();
		notify->set_notify_type(notify, NO_PROPOSAL_CHOSEN);
		response->add_payload(response, (payload_t*)notify);
		
		this->logger->log(this->logger, AUDIT,
						  "no connection for hosts %s...%s found, deleting IKE_SA",
						  me->get_string(me), other->get_string(other));
		return DESTROY_ME;
	}
	
	if (snprintf(name, sizeof(name), "%s{%d}",
				 this->connection->get_name(this->connection),
				 this->unique_id) > 0)
	{
		this->ike_sa->set_name(this->ike_sa, name);
	}
	this->ike_sa->apply_connection(this->ike_sa, this->connection);
	
	/* Precompute NAT-D hashes for incoming NAT notify comparison */
	ike_sa_id = request->get_ike_sa_id(request);
	this->natd_dst_hash = generate_natd_hash(this, ike_sa_id, me);
	this->natd_src_hash = generate_natd_hash(this, ike_sa_id, other);
	
	/* Iterate over all payloads. */
	payloads = request->get_payload_iterator(request);
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		switch (payload->get_type(payload))
		{
			case SECURITY_ASSOCIATION:
				sa_request = (sa_payload_t*)payload;
				break;
			case KEY_EXCHANGE:
				ke_request = (ke_payload_t*)payload;
				break;
			case NONCE:
				nonce_request = (nonce_payload_t*)payload;
				break;
			case NOTIFY:
			{
				status = process_notifys(this, (notify_payload_t*)payload);
				if (status == FAILED)
				{
					payloads->destroy(payloads);
					/* we return SUCCESS, returned FAILED means do next transaction */
					return SUCCESS;
				}
				if (status == DESTROY_ME)
				{
					payloads->destroy(payloads);
					return DESTROY_ME;
				}
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR|LEVEL1, 
								  "ignoring %s payload (%d)", 
								  mapping_find(payload_type_m, payload->get_type(payload)),
								  payload->get_type(payload));
				break;
			}
		}
	}
	payloads->destroy(payloads);
	
	/* check if we have all payloads */
	if (!(sa_request && ke_request && nonce_request))
	{
		notify_payload_t *notify = notify_payload_create();
		notify->set_notify_type(notify, INVALID_SYNTAX);
		response->add_payload(response, (payload_t*)notify);
		this->logger->log(this->logger, AUDIT, 
						  "request message incomplete, deleting IKE_SA");
		return DESTROY_ME;
	}
	
	{	/* process SA payload:
		 * -------------------
		 * - extract proposals
		 * - select our most preferred proposal found in extracted
		 *   - if no matches, return NO_PROPOSAL_CHOSEN
		 * - add sa payload with selected proposal
		 */
		sa_payload_t* sa_response;
		linked_list_t *proposal_list;
	
		proposal_list = sa_request->get_proposals(sa_request);
		this->proposal = this->connection->select_proposal(this->connection, proposal_list);
		destroy_proposal_list(proposal_list);
		if (this->proposal == NULL)
		{
			notify_payload_t *notify = notify_payload_create();
			notify->set_notify_type(notify, NO_PROPOSAL_CHOSEN);
			response->add_payload(response, (payload_t*)notify);
			this->logger->log(this->logger, AUDIT,
							  "request did not contain any acceptable proposals, deleting IKE_SA");
			return DESTROY_ME;
		}
		sa_response = sa_payload_create_from_proposal(this->proposal);	
		response->add_payload(response, (payload_t *)sa_response);
	}
	
	{	/* process KE payload:
		 * --------------------
		 * - check if used group match the selected proposal
		 *   - if not, stop with INVALID_KE_PAYLOAD
		 * - apply others public value to complete diffie hellman exchange
		 * - add our public value to response
		 */
		diffie_hellman_group_t used_group;
		ke_payload_t *ke_response;
		
		used_group = ke_request->get_dh_group_number(ke_request);
		
		if (!this->connection->check_dh_group(this->connection, used_group) ||
			(this->diffie_hellman = diffie_hellman_create(used_group)) == NULL)
		{
			u_int16_t notify_group;
			chunk_t notify_chunk;
			notify_payload_t *notify;
			iterator_t *iterator;
			payload_t *payload;
			
			notify_group = this->connection->get_dh_group(this->connection);
			this->logger->log(this->logger, AUDIT, 
							  "request used inacceptable DH group %s, sending INVALID_KE_PAYLOAD with %s, deleting IKE_SA",
							  mapping_find(diffie_hellman_group_m, used_group),
							  mapping_find(diffie_hellman_group_m, notify_group));
			
			/* remove already added payloads */
			iterator = response->get_payload_iterator(response);
			while (iterator->has_next(iterator))
			{
				iterator->current(iterator, (void**)&payload);
				iterator->remove(iterator);
				payload->destroy(payload);
			}
			iterator->destroy(iterator);
			
			notify_group = htons(notify_group);
			notify_chunk.ptr = (u_int8_t*)&notify_group;
			notify_chunk.len = sizeof(notify_group);
			notify = notify_payload_create();
			notify->set_notify_type(notify, INVALID_KE_PAYLOAD);
			notify->set_notification_data(notify, notify_chunk);
			response->add_payload(response, (payload_t*)notify);
			return DESTROY_ME;
		}
		this->diffie_hellman->set_other_public_value(this->diffie_hellman,
				ke_request->get_key_exchange_data(ke_request));
		
		/* build response */
		ke_response = ke_payload_create_from_diffie_hellman(this->diffie_hellman);
		response->add_payload(response, (payload_t*)ke_response);
	}
	
	{	/* process nonce payload:
		 * ----------------------
		 * - get nonce from payload
		 * - generate own nonce and add to reply
		 */
		nonce_payload_t *nonce_response;
		
		this->nonce_i = nonce_request->get_nonce(nonce_request);
		
		/* build response nonce */
		if (this->randomizer->allocate_pseudo_random_bytes(this->randomizer, 
			NONCE_SIZE, &this->nonce_r) != SUCCESS)
		{
			notify_payload_t *notify = notify_payload_create();
			notify->set_notify_type(notify, NO_PROPOSAL_CHOSEN);
			response->add_payload(response, (payload_t*)notify);
			this->logger->log(this->logger, AUDIT,
							  "could not get random bytes for nonce, deleting IKE_SA");
			return DESTROY_ME;
		}
		nonce_response = nonce_payload_create();
		nonce_response->set_nonce(nonce_response, this->nonce_r);
		response->add_payload(response, (payload_t *)nonce_response);
	}

	{	/* processs NATT stuff:
		 * --------------------
		 * - check if we or other is behind NAT
		 * - enable NATT if so
		 * - build NAT detection notifys for reply
		 */
		notify_payload_t *notify;
		
		if ((!this->natd_src_seen && this->natd_dst_seen) ||
		    (this->natd_src_seen && !this->natd_dst_seen))
		{
			notify = notify_payload_create();
			notify->set_notify_type(notify, INVALID_SYNTAX);
			response->add_payload(response, (payload_t*)notify);
			this->logger->log(this->logger, AUDIT,
							  "request contained wrong number of NAT-D payloads, deleting IKE_SA");
			return DESTROY_ME;
		}
		if (this->natd_dst_seen && !this->natd_dst_matched)
		{
			this->ike_sa->enable_natt(this->ike_sa, TRUE);
		}
		if (this->natd_src_seen && !this->natd_src_matched)
		{
			this->ike_sa->enable_natt(this->ike_sa, FALSE);
		}
		/* build response NAT DETECTION notifys, if remote supports it */
		if (this->natd_src_seen || this->natd_dst_seen)
		{
			/* N(NAT_DETECTION_SOURCE_IP) */
			notify = build_natd_payload(this, NAT_DETECTION_SOURCE_IP, me);
			response->add_payload(response, (payload_t*)notify);
			
			/* N(NAT_DETECTION_DESTINATION_IP) */
			notify = build_natd_payload(this, NAT_DETECTION_DESTINATION_IP, other);
			response->add_payload(response, (payload_t*)notify);
		}
	}

	/* derive all the keys used in the IKE_SA */
	if (this->ike_sa->derive_keys(this->ike_sa, this->proposal, 
								  this->diffie_hellman, 
								  this->nonce_i, this->nonce_r,
								  FALSE, NULL, NULL) != SUCCESS)
	{
		notify_payload_t *notify = notify_payload_create();
		notify->set_notify_type(notify, NO_PROPOSAL_CHOSEN);
		response->add_payload(response, (payload_t*)notify);
		this->logger->log(this->logger, AUDIT, 
						  "transform objects could not be created from selected proposal, deleting IKE_SA");
		return DESTROY_ME;
	}
	
	this->ike_sa->set_lifetimes(this->ike_sa, 
					this->connection->get_soft_lifetime(this->connection),
					this->connection->get_hard_lifetime(this->connection));
	
	{	/* create ike_auth transaction, which will store informations for us */
		packet_t *response_packet;
		chunk_t request_chunk, response_chunk;
		ike_auth_t *ike_auth;
		
		/* we normally do not generate the message. But we need the generated message
		 * for authentication in the next state, so we do it here. This is not problematic,
		 * as we don't use a crypter/signer in ike_sa_init... */
		if (response->generate(response, NULL, NULL, &response_packet) != SUCCESS)
		{
			this->logger->log(this->logger, AUDIT, 
							  "error in response generation, deleting IKE_SA");
			return DESTROY_ME;
		}
		response_packet->destroy(response_packet);
		request_chunk = request->get_packet_data(request);
		response_chunk = response->get_packet_data(response);
		
		/* create next transaction, for which we except a message */
		ike_auth = ike_auth_create(this->ike_sa);
		ike_auth->set_config(ike_auth, this->connection, this->policy);
		ike_auth->set_reqid(ike_auth, this->reqid);
		this->connection = NULL;
		this->policy = NULL;
		ike_auth->set_nonces(ike_auth,
							 chunk_clone(this->nonce_i),
							 chunk_clone(this->nonce_r));
		ike_auth->set_init_messages(ike_auth, request_chunk, response_chunk);
		*next = (transaction_t*)ike_auth;
	}
	
	/* everything went fine. Now we set a timeout to destroy half initiated IKE_SAs */
	timeout = charon->configuration->get_half_open_ike_sa_timeout(charon->configuration);
	if (timeout)
	{
		job_t *job = (job_t*)delete_ike_sa_job_create(
						this->ike_sa->get_id(this->ike_sa), FALSE);
		charon->event_queue->add_relative(charon->event_queue, job, timeout);
	}
	/* set new state */
	this->ike_sa->set_state(this->ike_sa, IKE_CONNECTING);
	
	return SUCCESS;
}


/**
 * Implementation of transaction_t.conclude
 */
static status_t conclude(private_ike_sa_init_t *this, message_t *response, 
						 transaction_t **next)
{
	u_int64_t responder_spi;
	ike_sa_id_t *ike_sa_id;
	iterator_t *payloads;
	host_t *me, *other;
	sa_payload_t *sa_payload = NULL;
	ke_payload_t *ke_payload = NULL;
	nonce_payload_t *nonce_payload = NULL;
	status_t status;
	
	/* check message type */
	if (response->get_exchange_type(response) != IKE_SA_INIT)
	{
		this->logger->log(this->logger, ERROR, 
						  "IKE_SA_INIT response of invalid type, deleting IKE_SA");
		return DESTROY_ME;
	}
	
	/* allow setting of next transaction in other functions */
	this->next = next;
	
	me = this->connection->get_my_host(this->connection);
	other = this->connection->get_other_host(this->connection);
	
	/* check if SPI has been updated, but apply only if all goes ok later */
	responder_spi = response->get_responder_spi(response);
	if (responder_spi == 0)
	{
		this->logger->log(this->logger, ERROR, 
						  "response contained a SPI of zero, deleting IKE_SA");
		return DESTROY_ME;
	}
	
	/* Precompute NAT-D hashes for later comparison */
	ike_sa_id = response->get_ike_sa_id(response);
	this->natd_src_hash = generate_natd_hash(this, ike_sa_id, other);
	this->natd_dst_hash = generate_natd_hash(this, ike_sa_id, me);
	
	/* Iterate over all payloads to collect them */
	payloads = response->get_payload_iterator(response);
	while (payloads->has_next(payloads))
	{ 
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		
		switch (payload->get_type(payload))
		{
			case SECURITY_ASSOCIATION:
			{
				sa_payload = (sa_payload_t*)payload;
				break;
			}
			case KEY_EXCHANGE:
			{
				ke_payload = (ke_payload_t*)payload;
				break;
			}
			case NONCE:
			{
				nonce_payload = (nonce_payload_t*)payload;
				break;
			}
			case NOTIFY:
			{
				status = process_notifys(this, (notify_payload_t*)payload);
				if (status == FAILED)
				{
					payloads->destroy(payloads);
					/* we return SUCCESS, returned FAILED means do next transaction */
					return SUCCESS;
				}
				if (status == DESTROY_ME)
				{
					payloads->destroy(payloads);
					return status;
				}
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR, "ignoring payload %s (%d)",
								  mapping_find(payload_type_m, payload->get_type(payload)),
								  payload->get_type(payload));
				break;
			}
		}
	}
	payloads->destroy(payloads);
	
	if (!(nonce_payload && sa_payload && ke_payload))
	{
		this->logger->log(this->logger, AUDIT, "response message incomplete, deleting IKE_SA");
		return DESTROY_ME;
	}
	
	{	/* process SA payload:
		 * -------------------
		 * - get proposals from it
		 * - check if peer selected a proposal
		 * - verify it's selection againts our set
		 */
		proposal_t *proposal;
		linked_list_t *proposal_list;
		
		/* get the list of selected proposals, the peer has to select only one proposal */
		proposal_list = sa_payload->get_proposals (sa_payload);
		if (proposal_list->get_count(proposal_list) != 1)
		{
			this->logger->log(this->logger, AUDIT, 
							  "response did not contain a single proposal, deleting IKE_SA");
			while (proposal_list->remove_last(proposal_list, (void**)&proposal) == SUCCESS)
			{
				proposal->destroy(proposal);
			}
			proposal_list->destroy(proposal_list);
			return DESTROY_ME;
		}
		
		/* we have to re-check if the others selection is valid */
		this->proposal = this->connection->select_proposal(this->connection, proposal_list);
		destroy_proposal_list(proposal_list);
		
		if (this->proposal == NULL)
		{
			this->logger->log(this->logger, AUDIT, 
							  "peer selected a proposal we did not offer, deleting IKE_SA");
			return DESTROY_ME;
		}
	}
	
	{	/* process KE payload:
		 * -------------------
		 * - extract others public value
		 * - complete diffie-hellman exchange
		 */
		this->diffie_hellman->set_other_public_value(this->diffie_hellman,
				ke_payload->get_key_exchange_data(ke_payload));
	}
	
	{	/* process NONCE payload:
		 * ----------------------
		 * - extract nonce used for key derivation */
		this->nonce_r = nonce_payload->get_nonce(nonce_payload);
	}
	
	{	/* process NATT stuff:
		 * -------------------
		 * - check if we or other is NATted
		 * - switch to port 4500 if so
		 */
		if ((!this->natd_dst_seen && this->natd_src_seen) ||
			(this->natd_dst_seen && !this->natd_src_seen))
		{
			this->logger->log(this->logger, AUDIT, 
							"request contained wrong number of NAT-D payloads, deleting IKE_SA");
			return DESTROY_ME;
		}
		if (this->natd_src_seen && !this->natd_src_matched)
		{
			this->ike_sa->enable_natt(this->ike_sa, FALSE);
		}
		if (this->natd_dst_seen && !this->natd_dst_matched)
		{
			this->ike_sa->enable_natt(this->ike_sa, TRUE);
		}
		if (this->ike_sa->is_natt_enabled(this->ike_sa))
		{
			me = this->ike_sa->get_my_host(this->ike_sa);
			me->set_port(me, IKEV2_NATT_PORT);
			other = this->ike_sa->get_other_host(this->ike_sa);
			other->set_port(other, IKEV2_NATT_PORT);
			
			this->logger->log(this->logger, CONTROL|LEVEL1, "switching to port %d", IKEV2_NATT_PORT);
		}
	}
	
	/* because we are original initiator we have to update the responder SPI to the new one */
	ike_sa_id = this->ike_sa->get_id(this->ike_sa);
	ike_sa_id->set_responder_spi(ike_sa_id, responder_spi);
	
	/* derive all the keys used in the IKE_SA */
	if (this->ike_sa->derive_keys(this->ike_sa, this->proposal, 
								  this->diffie_hellman, 
								  this->nonce_i, this->nonce_r,
								  TRUE, NULL, NULL) != SUCCESS)
	{
		this->logger->log(this->logger, AUDIT, 
						  "transform objects could not be created from selected proposal, deleting IKE_SA");
		return DESTROY_ME;
	}
	
	this->ike_sa->set_lifetimes(this->ike_sa, 
					this->connection->get_soft_lifetime(this->connection),
					this->connection->get_hard_lifetime(this->connection));
	
	{	/* create ike_auth transaction, which will continue IKE_SA setup */
		chunk_t request_chunk, response_chunk;
		ike_auth_t *ike_auth;
		
		request_chunk = this->message->get_packet_data(this->message);
		response_chunk = response->get_packet_data(response);
		
		/* create next transaction, for which we except a message */
		ike_auth = ike_auth_create(this->ike_sa);
		ike_auth->set_config(ike_auth, this->connection, this->policy);
		ike_auth->set_reqid(ike_auth, this->reqid);
		this->connection = NULL;
		this->policy = NULL;
		ike_auth->set_nonces(ike_auth,
							 chunk_clone(this->nonce_i),
							 chunk_clone(this->nonce_r));
		ike_auth->set_init_messages(ike_auth, request_chunk, response_chunk);
		*next = (transaction_t*)ike_auth;
	}
	
	return SUCCESS;
}

static void destroy(private_ike_sa_init_t *this)
{
	DESTROY_IF(this->message);
	DESTROY_IF(this->diffie_hellman);
	DESTROY_IF(this->proposal);
	DESTROY_IF(this->connection);
	DESTROY_IF(this->policy);
	chunk_free(&this->nonce_i);
	chunk_free(&this->nonce_r);
	this->randomizer->destroy(this->randomizer);
	this->nat_hasher->destroy(this->nat_hasher);
	chunk_free(&this->natd_src_hash);
	chunk_free(&this->natd_dst_hash);
	free(this);
}

/*
 * Described in header.
 */
ike_sa_init_t *ike_sa_init_create(ike_sa_t *ike_sa)
{
	static u_int unique_id = 0;
	private_ike_sa_init_t *this = malloc_thing(private_ike_sa_init_t);

	/* transaction interface functions */
	this->public.transaction.get_request = (status_t(*)(transaction_t*,message_t**))get_request;
	this->public.transaction.get_response = (status_t(*)(transaction_t*,message_t*,message_t**,transaction_t**))get_response;
	this->public.transaction.conclude = (status_t(*)(transaction_t*,message_t*,transaction_t**))conclude;
	this->public.transaction.get_message_id = (u_int32_t(*)(transaction_t*))get_message_id;
	this->public.transaction.requested = (u_int32_t(*)(transaction_t*))requested;
	this->public.transaction.destroy = (void(*)(transaction_t*))destroy;
	
	/* public functions */
	this->public.set_config = (void(*)(ike_sa_init_t*,connection_t*,policy_t*))set_config;
	this->public.set_reqid = (void(*)(ike_sa_init_t*,u_int32_t))set_reqid;
	this->public.use_dh_group = (bool(*)(ike_sa_init_t*,diffie_hellman_group_t))use_dh_group;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->message_id = 0;
	this->message = NULL;
	this->requested = 0;
	this->diffie_hellman = NULL;
	this->nonce_i = CHUNK_INITIALIZER;
	this->nonce_r = CHUNK_INITIALIZER;
	this->connection = NULL;
	this->policy = NULL;
	this->proposal = NULL;
	this->unique_id = ++unique_id;
	this->reqid = 0;
	this->randomizer = randomizer_create();
	this->nat_hasher = hasher_create(HASH_SHA1);
	this->natd_src_hash = CHUNK_INITIALIZER;
	this->natd_dst_hash = CHUNK_INITIALIZER;
	this->natd_src_seen = FALSE;
	this->natd_dst_seen = FALSE;
	this->natd_src_matched = FALSE;
	this->natd_dst_matched = FALSE;
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);
	
	return &this->public;
}
