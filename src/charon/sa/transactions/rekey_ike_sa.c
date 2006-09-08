/**
 * @file rekey_ike_sa.c
 *
 * @brief Implementation of rekey_ike_sa_t transaction.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#include "rekey_ike_sa.h"

#include <string.h>

#include <daemon.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <sa/transactions/delete_ike_sa.h>
#include <utils/randomizer.h>


typedef struct private_rekey_ike_sa_t private_rekey_ike_sa_t;

/**
 * Private members of a rekey_ike_sa_t object..
 */
struct private_rekey_ike_sa_t {
	
	/**
	 * Public methods and transaction_t interface.
	 */
	rekey_ike_sa_t public;
	
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
	 * IKE_SA we set up, replaces ike_sa
	 */
	ike_sa_t *new_sa;
	
	/**
	 * Connection used to replace IKE_SA
	 */
	connection_t *connection;
	
	/**
	 * initiator chosen nonce
	 */
	chunk_t nonce_i;
	
	/**
	 * responder chosen nonce
	 */
	chunk_t nonce_r;
	
	/**
	 * lower of the nonces of a simultaneus rekeying request
	 */
	chunk_t nonce_s;
	
	/**
	 * Diffie hellman to generate new shared secret
	 */
	diffie_hellman_t *diffie_hellman;
	
	/**
	 * negotiated proposal to use
	 */
	proposal_t *proposal;
	
	/**
	 * Have we lost the simultaneous rekeying nonce compare?
	 */
	bool lost;
	
	/**
	 * source of randomness for nonces
	 */
	randomizer_t *randomizer;
	
	/**
	 * next transaction processed by the IKE_SA
	 */
	transaction_t **next;
	
	/**
	 * Assigned logger.
	 */
	logger_t *logger;
};

/**
 * Implementation of transaction_t.get_message_id.
 */
static u_int32_t get_message_id(private_rekey_ike_sa_t *this)
{
	return this->message_id;
}

/**
 * Implementation of transaction_t.requested.
 */
static u_int32_t requested(private_rekey_ike_sa_t *this)
{
	return this->requested++;
}


/**
 * Implementation of rekey_ike_sa_t.use_dh_group.
 */
static void use_dh_group(private_rekey_ike_sa_t *this, diffie_hellman_group_t dh_group)
{
	this->diffie_hellman = diffie_hellman_create(dh_group);
}

/**
 * Implementation of rekey_ike_sa_t.cancel.
 */
static void cancel(private_rekey_ike_sa_t *this)
{
	this->lost = TRUE;
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
static status_t get_request(private_rekey_ike_sa_t *this, message_t **result)
{
	message_t *request;
	host_t *me, *other;
	
	/* check if we already have built a message (retransmission) */
	if (this->message)
	{
		*result = this->message;
		return SUCCESS;
	}
	
	/* check for correct state, except when retrying with another dh group */
	if (this->ike_sa->get_state(this->ike_sa) != IKE_ESTABLISHED &&
	    !this->diffie_hellman)
	{
		this->logger->log(this->logger, ERROR,
						  "tried to rekey in state %s, aborted",
						  mapping_find(ike_sa_state_m,
									   this->ike_sa->get_state(this->ike_sa)));
		return FAILED;
	}
	
	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	
	/* build the request */
	request = message_create();
	request->set_source(request, me->clone(me));
	request->set_destination(request, other->clone(other));
	request->set_exchange_type(request, CREATE_CHILD_SA);
	request->set_request(request, TRUE);
	request->set_ike_sa_id(request, this->ike_sa->get_id(this->ike_sa));
	*result = request;
	this->message = request;
	
	{	/* build SA payload */
		sa_payload_t *sa_payload;
		linked_list_t *proposals;
		ike_sa_id_t *ike_sa_id;
		iterator_t *iterator;
		proposal_t *proposal;
		u_int64_t spi;
		
		/* get a connection to replace current IKE_SA */
		this->connection = charon->connections->get_connection_by_name(
										charon->connections,
										this->ike_sa->get_name(this->ike_sa));
		/* if connection lookup by name fails, try it with the hosts */
		if (this->connection == NULL)
		{
			this->connection = charon->connections->get_connection_by_hosts(
										charon->connections,
										me, other);
			if (this->connection == NULL)
			{
				this->logger->log(this->logger, ERROR,
								  "no connection found to rekey IKE_SA");
				return FAILED;
			}
		}
		
		/* create a new SA */
		ike_sa_id = ike_sa_id_create(0, 0, TRUE);
		this->new_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager,
														ike_sa_id);
		spi = ike_sa_id->get_initiator_spi(ike_sa_id);
		ike_sa_id->destroy(ike_sa_id);
		
		proposals = this->connection->get_proposals(this->connection);
		iterator = proposals->create_iterator(proposals, TRUE);
		while (iterator->iterate(iterator, (void**)&proposal))
		{
			proposal->set_spi(proposal, spi);
		}
		iterator->destroy(iterator);
		
		sa_payload = sa_payload_create_from_proposal_list(proposals);
		destroy_proposal_list(proposals);
		request->add_payload(request, (payload_t*)sa_payload);
	}
	
	{	/* build the NONCE payload for us (initiator) */
		nonce_payload_t *nonce_payload;
		
		if (this->randomizer->allocate_pseudo_random_bytes(this->randomizer, 
			NONCE_SIZE, &this->nonce_i) != SUCCESS)
		{
			return FAILED;
		}
		nonce_payload = nonce_payload_create();
		nonce_payload->set_nonce(nonce_payload, this->nonce_i);
		request->add_payload(request, (payload_t*)nonce_payload);
	}
	
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
			return FAILED;
		}
	}
	
	{	/* build the KE payload from the DH object */
		ke_payload_t *ke_payload;
		
		ke_payload = ke_payload_create_from_diffie_hellman(this->diffie_hellman);
		request->add_payload(request, (payload_t*)ke_payload);
	}
	
	this->message_id = this->ike_sa->get_next_message_id(this->ike_sa);
	request->set_message_id(request, this->message_id);
	
	/* register us as rekeying to detect multiple rekeying */
	this->ike_sa->set_state(this->ike_sa, IKE_REKEYING);
	this->ike_sa->set_rekeying_transaction(this->ike_sa, &this->public);
	
	return SUCCESS;
}

/**
 * Handle all kind of notifys
 */
static status_t process_notifys(private_rekey_ike_sa_t *this, notify_payload_t *notify_payload)
{
	notify_type_t notify_type = notify_payload->get_notify_type(notify_payload);
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "process notify type %s",
					  mapping_find(notify_type_m, notify_type));

	switch (notify_type)
	{
		case NO_PROPOSAL_CHOSEN:
		{
			this->logger->log(this->logger, AUDIT, 
							  "received a NO_PROPOSAL_CHOSEN notify, IKE_SA rekeying failed");
			return FAILED;
		}
		case INVALID_KE_PAYLOAD:
		{
			chunk_t notify_data;
			diffie_hellman_group_t dh_group, old_dh_group;
			rekey_ike_sa_t *retry;
			
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
								  "requested DH group not acceptable, IKE_SA rekeying failed");
				return FAILED;
			}
			retry = rekey_ike_sa_create(this->ike_sa);
			retry->use_dh_group(retry, dh_group);
			*this->next = (transaction_t*)retry;
			return FAILED;
		}
		default:
		{
			if (notify_type < 16383)
			{
				this->logger->log(this->logger, AUDIT, 
								  "received %s notify error (%d, IKE_SA rekeying failed",
								  mapping_find(notify_type_m, notify_type),
								  notify_type);
				return FAILED;	
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
 * Switch to the new created IKE_SA
 */
static status_t switchto_new_sa(private_rekey_ike_sa_t* this, bool initiator)
{
	identification_t *my_id, *other_id;
	host_t *my_host, *other_host;
	char *name;
	
	my_id = this->ike_sa->get_my_id(this->ike_sa);
	other_id = this->ike_sa->get_other_id(this->ike_sa);
	my_host = this->ike_sa->get_my_host(this->ike_sa);
	other_host = this->ike_sa->get_other_host(this->ike_sa);
	name = this->ike_sa->get_name(this->ike_sa);
	
	this->new_sa->set_my_id(this->new_sa, my_id->clone(my_id));
	this->new_sa->set_other_id(this->new_sa, other_id->clone(other_id));
	this->new_sa->set_my_host(this->new_sa, my_host->clone(my_host));
	this->new_sa->set_other_host(this->new_sa, other_host->clone(other_host));
	this->new_sa->set_name(this->new_sa, name);
	
	if (this->new_sa->derive_keys(this->new_sa, this->proposal,
								  this->diffie_hellman, 
								  this->nonce_i, this->nonce_r, initiator,
								  this->ike_sa->get_child_prf(this->ike_sa),
								  this->ike_sa->get_prf(this->ike_sa)
								 ) != SUCCESS)
	{
		return FAILED;
	}
	
	this->new_sa->set_state(this->new_sa, IKE_ESTABLISHED);
	
	this->new_sa->set_lifetimes(this->new_sa,
						this->connection->get_soft_lifetime(this->connection),
						this->connection->get_hard_lifetime(this->connection));
	return SUCCESS;
}

/**
 * Build a notify message.
 */
static void build_notify(notify_type_t type, chunk_t data, message_t *message, bool flush_message)
{
	notify_payload_t *notify;
	
	if (flush_message)
	{
		payload_t *payload;
		iterator_t *iterator = message->get_payload_iterator(message);
		while (iterator->iterate(iterator, (void**)&payload))
		{
			payload->destroy(payload);
			iterator->remove(iterator);
		}
		iterator->destroy(iterator);
	}
	
	notify = notify_payload_create();
	notify->set_notify_type(notify, type);
	notify->set_notification_data(notify, data);
	message->add_payload(message, (payload_t*)notify);
}

/**
 * Implementation of transaction_t.get_response.
 */
static status_t get_response(private_rekey_ike_sa_t *this, message_t *request, 
							 message_t **result, transaction_t **next)
{
	host_t *me, *other;
	message_t *response;
	status_t status;
	iterator_t *payloads, *iterator;
	child_sa_t *child_sa;
	sa_payload_t *sa_request = NULL;
	nonce_payload_t *nonce_request = NULL;
	ke_payload_t *ke_request = NULL;
	nonce_payload_t *nonce_response;
	
	/* check if we already have built a response (retransmission) */
	if (this->message)
	{
		*result = this->message;
		return SUCCESS;
	}
	
	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	this->message_id = request->get_message_id(request);
	
	/* set up response */
	response = message_create();
	response->set_source(response, me->clone(me));
	response->set_destination(response, other->clone(other));
	response->set_exchange_type(response, CREATE_CHILD_SA);
	response->set_request(response, FALSE);
	response->set_message_id(response, this->message_id);
	response->set_ike_sa_id(response, this->ike_sa->get_id(this->ike_sa));
	this->message = response;
	*result = response;
	
	/* check message type */
	if (request->get_exchange_type(request) != CREATE_CHILD_SA)
	{
		this->logger->log(this->logger, ERROR,
						  "CREATE_CHILD_SA response of invalid type, aborted");
		return FAILED;
	}
	
	/* if we already initiate a delete, we do not allow rekeying */
	if (this->ike_sa->get_state(this->ike_sa) == IKE_DELETING)
	{
		build_notify(NO_PROPOSAL_CHOSEN, CHUNK_INITIALIZER, response, TRUE);
		this->logger->log(this->logger, CONTROL,
						  "unable to rekey, as delete in progress. Sending NO_PROPOSAL_CHOSEN");
		return FAILED;
	}
	
	/* if we have a CHILD which is "half-open", we do not allow rekeying */
	iterator = this->ike_sa->create_child_sa_iterator(this->ike_sa);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		child_sa_state_t state = child_sa->get_state(child_sa);
		if (state == CHILD_CREATED ||
			state == CHILD_REKEYING ||
			state == CHILD_DELETING)
		{
			build_notify(NO_PROPOSAL_CHOSEN, CHUNK_INITIALIZER, response, TRUE);
			this->logger->log(this->logger, CONTROL,
							  "unable to rekey, one CHILD_SA is half open. Sending NO_PROPOSAL_CHOSEN");
			iterator->destroy(iterator);
			return FAILED;
		}
	}
	iterator->destroy(iterator);
	
	/* apply for notify processing */
	this->next = next;
	
	
	/* get a connection to replace current IKE_SA */
	this->connection = charon->connections->get_connection_by_name(
					charon->connections, this->ike_sa->get_name(this->ike_sa));
	/* if connection lookup by name fails, try it with the hosts */
	if (this->connection == NULL)
	{
		this->connection = charon->connections->get_connection_by_hosts(
								charon->connections, me, other);
		if (this->connection == NULL)
		{
			this->logger->log(this->logger, ERROR,
								"no connection found to rekey IKE_SA, sending NO_RROPOSAL_CHOSEN");
			build_notify(NO_PROPOSAL_CHOSEN, CHUNK_INITIALIZER, response, TRUE);
			return FAILED;
		}
	}
	
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
			case NONCE:
				nonce_request = (nonce_payload_t*)payload;
				break;
			case KEY_EXCHANGE:
			{
				ke_request = (ke_payload_t*)payload;
				break;
			}
			case NOTIFY:
			{
				status = process_notifys(this, (notify_payload_t*)payload);
				if (status != SUCCESS)
				{
					payloads->destroy(payloads);
					return status;
				}
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR, "ignoring %s payload (%d)", 
								  mapping_find(payload_type_m, payload->get_type(payload)),
								  payload->get_type(payload));
				break;
			}
		}
	}
	payloads->destroy(payloads);
	
	/* check if we have all payloads */
	if (!(sa_request && nonce_request && ke_request))
	{
		build_notify(INVALID_SYNTAX, CHUNK_INITIALIZER, response, TRUE);
		this->logger->log(this->logger, AUDIT, 
						  "request message incomplete, IKE_SA rekeying failed");
		return FAILED;
	}
	
	{	/* process nonce payload */
		this->nonce_i = nonce_request->get_nonce(nonce_request);
		if (this->randomizer->allocate_pseudo_random_bytes(this->randomizer, 
			NONCE_SIZE, &this->nonce_r) != SUCCESS)
		{
			build_notify(NO_PROPOSAL_CHOSEN, CHUNK_INITIALIZER, response, TRUE);
			return FAILED;
		}
		nonce_response = nonce_payload_create();
		nonce_response->set_nonce(nonce_response, this->nonce_r);
	}
	
	{	/* process SA payload */
		linked_list_t *proposal_list;
		sa_payload_t *sa_response;
		u_int64_t spi;
		ike_sa_id_t *ike_sa_id;
		
		sa_response = sa_payload_create();
		/* get proposals from request, and select one with ours */
		proposal_list = sa_request->get_proposals(sa_request);
		this->logger->log(this->logger, CONTROL|LEVEL1, "selecting proposals:");
		this->proposal = this->connection->select_proposal(this->connection, proposal_list);
		destroy_proposal_list(proposal_list);
		
		/* do we have a proposal? */
		if (this->proposal == NULL)
		{
			this->logger->log(this->logger, AUDIT, 
							  "no proposals acceptable to rekey IKE_SA, sending NO_PROPOSAL_CHOSEN");
			build_notify(NO_PROPOSAL_CHOSEN, CHUNK_INITIALIZER, response, TRUE);
			return FAILED;
		}
		
		/* create IKE_SA with new SPIs */
		spi = this->proposal->get_spi(this->proposal);
		ike_sa_id = ike_sa_id_create(spi, 0, FALSE);
		this->new_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager,
														ike_sa_id);
		spi = ike_sa_id->get_responder_spi(ike_sa_id);
		ike_sa_id->destroy(ike_sa_id);
		this->proposal->set_spi(this->proposal, spi);
		
		sa_response->add_proposal(sa_response, this->proposal);
		response->add_payload(response, (payload_t*)sa_response);
		/* add nonce after sa payload */
		response->add_payload(response, (payload_t *)nonce_response);
	}
	
	{	/* process KE payload */
		diffie_hellman_group_t used_group;
		ke_payload_t *ke_response;
		
		used_group = ke_request->get_dh_group_number(ke_request);
		
		if (!this->connection->check_dh_group(this->connection, used_group) ||
			(this->diffie_hellman = diffie_hellman_create(used_group)) == NULL)
		{
			u_int16_t notify_group;
			chunk_t notify_chunk;
			
			notify_group = this->connection->get_dh_group(this->connection);
			this->logger->log(this->logger, AUDIT, 
							  "request used inacceptable DH group %s, sending INVALID_KE_PAYLOAD with %s",
							  mapping_find(diffie_hellman_group_m, used_group),
							  mapping_find(diffie_hellman_group_m, notify_group));
			
			notify_group = htons(notify_group);
			notify_chunk.ptr = (u_int8_t*)&notify_group;
			notify_chunk.len = sizeof(notify_group);
			build_notify(INVALID_KE_PAYLOAD, notify_chunk, response, TRUE);
			return FAILED;
		}
		this->diffie_hellman->set_other_public_value(this->diffie_hellman,
								ke_request->get_key_exchange_data(ke_request));
		
		/* build response */
		ke_response = ke_payload_create_from_diffie_hellman(this->diffie_hellman);
		response->add_payload(response, (payload_t*)ke_response);
	}
	
	status = switchto_new_sa(this, FALSE);
	if (status != SUCCESS)
	{
		return status;
	}
	
	/* IKE_SA successfully created. If another transaction is already rekeying
	 * this SA, our lower nonce must be registered for a later nonce compare. */
	{
		private_rekey_ike_sa_t *other;
		
		other = this->ike_sa->get_rekeying_transaction(this->ike_sa);
		if (other)
		{
			/* store our lower nonce in the simultaneus transaction, we 
			 * will later compare it against his nonces when we calls conclude().
			 * We do not adopt childrens yet, as we don't know if we'll win
			 * the race...
			 */
			if (memcmp(this->nonce_i.ptr, this->nonce_r.ptr,
				min(this->nonce_i.len, this->nonce_r.len)) < 0)
			{
				other->nonce_s = chunk_clone(this->nonce_i);
			}
			else
			{
				other->nonce_s = chunk_clone(this->nonce_r);
			}
			/* overwrite "other" in IKE_SA, allows "other" to access "this" */
			this->ike_sa->set_rekeying_transaction(this->ike_sa, &this->public);
		}
		else
		{
			/* if we have no simultaneus transaction, we can safely adopt 
			 * all children and complete. */
			this->new_sa->adopt_children(this->new_sa, this->ike_sa);
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, this->new_sa);
			this->new_sa = NULL;
		}
		this->ike_sa->set_state(this->ike_sa, IKE_REKEYING);
	}
	
	return SUCCESS;
}

/**
 * Implementation of transaction_t.conclude
 */
static status_t conclude(private_rekey_ike_sa_t *this, message_t *response, 
						 transaction_t **next)
{
	iterator_t *payloads;
	host_t *me, *other;
	sa_payload_t *sa_payload = NULL;
	nonce_payload_t *nonce_payload = NULL;
	ke_payload_t *ke_payload = NULL;
	private_rekey_ike_sa_t *other_trans;
	status_t status;
	
	/* check message type */
	if (response->get_exchange_type(response) != CREATE_CHILD_SA)
	{
		this->logger->log(this->logger, ERROR,
						  "CREATE_CHILD_SA response of invalid type, aborting");
		return FAILED;
	}
	
	me = this->ike_sa->get_my_host(this->ike_sa);
	other = this->ike_sa->get_other_host(this->ike_sa);
	
	/* apply for notify processing */
	this->next = next;
	
	/* Iterate over all payloads to collect them */
	payloads = response->get_payload_iterator(response);
	while (payloads->has_next(payloads))
	{
		payload_t *payload;
		payloads->current(payloads, (void**)&payload);
		switch (payload->get_type(payload))
		{
			case SECURITY_ASSOCIATION:
				sa_payload = (sa_payload_t*)payload;
				break;
			case NONCE:
				nonce_payload = (nonce_payload_t*)payload;
				break;
			case KEY_EXCHANGE:
				ke_payload = (ke_payload_t*)payload;
				break;
			case NOTIFY:
			{
				status = process_notifys(this, (notify_payload_t*)payload);
				if (status != SUCCESS)
				{
					payloads->destroy(payloads);
					return status;
				}
				break;
			}
			default:
			{
				this->logger->log(this->logger, ERROR, "ignoring %s payload (%d)", 
								  mapping_find(payload_type_m, payload->get_type(payload)),
								  payload->get_type(payload));
				break;
			}
		}
	}
	payloads->destroy(payloads);
	
	if (!(sa_payload && nonce_payload && ke_payload))
	{
		this->logger->log(this->logger, AUDIT, "response message incomplete, rekeying IKE_SA failed");
		return FAILED;
	}
	
	{	/* process NONCE payload  */
		this->nonce_r = nonce_payload->get_nonce(nonce_payload);
	}
	
	{	/* process SA payload */
		linked_list_t *proposal_list;
		ike_sa_id_t *ike_sa_id;
		u_int64_t spi;
		
		proposal_list = sa_payload->get_proposals(sa_payload);
		/* we have to re-check here if other's selection is valid */
		this->proposal = this->connection->select_proposal(this->connection, proposal_list);
		destroy_proposal_list(proposal_list);
		
		if (this->proposal == NULL)
		{
			this->logger->log(this->logger, AUDIT, 
							  "no proposal selected, rekeying IKE_SA failed");
			return FAILED;
		}
		spi = this->proposal->get_spi(this->proposal);
		ike_sa_id = this->new_sa->get_id(this->new_sa);
		ike_sa_id->set_responder_spi(ike_sa_id, spi);	
	}
	
	{	/* process KE payload */
		this->diffie_hellman->set_other_public_value(this->diffie_hellman,
							ke_payload->get_key_exchange_data(ke_payload));
	}
	
	if (switchto_new_sa(this, TRUE) != SUCCESS)
	{
		/* this should not happen. But if, we destroy both SAs */
		*next = (transaction_t*)delete_ike_sa_create(this->new_sa);
		return DESTROY_ME;
	}
	
	/* IKE_SA successfully created. If the other peer initiated rekeying
	 * in the meantime, we detect this by comparing the rekeying_transaction
	 * of the SA. If it changed, we are not alone. Then we must compare the nonces.
	 * If no simultaneous rekeying is going on, we just initiate the delete of
	 * the superseded SA. */
	other_trans = this->ike_sa->get_rekeying_transaction(this->ike_sa);
	this->ike_sa->set_rekeying_transaction(this->ike_sa, NULL);
	
	if (this->nonce_s.ptr)
	{	/* simlutaneous rekeying is going on, not so good */
		chunk_t this_lowest;
		
		/* first get our lowest nonce */
		if (memcmp(this->nonce_i.ptr, this->nonce_r.ptr,
			min(this->nonce_i.len, this->nonce_r.len)) < 0)
		{
			this_lowest = this->nonce_i;
		}
		else
		{
			this_lowest = this->nonce_r;
		}
		/* then compare against other lowest nonce */
		if (memcmp(this_lowest.ptr, this->nonce_s.ptr,
			min(this_lowest.len, this->nonce_s.len)) < 0)
		{
			this->logger->log(this->logger, ERROR,
								"detected simultaneous IKE_SA rekeying, deleting ours");
			this->lost = TRUE;
		}
		else
		{
			this->logger->log(this->logger, ERROR,
								"detected simultaneous IKE_SA rekeying, but ours is preferred");
		}
		if (this->lost)
		{
			/* the other has won, he gets our children */
			other_trans->new_sa->adopt_children(other_trans->new_sa, this->ike_sa);
			/* we have lost simlutaneous rekeying, delete the SA we just have created */
			this->new_sa->delete(this->new_sa);
		}
		/* other trans' SA is still not checked in, so do it now. It's SA will get
		 * deleted by remote peer. */
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, other_trans->new_sa);
		other_trans->new_sa = NULL;
	}
	
	if (!this->lost)
	{
		/* we have won. delete old IKE_SA, and migrate all children */
		*next = (transaction_t*)delete_ike_sa_create(this->ike_sa);
		this->new_sa->adopt_children(this->new_sa, this->ike_sa);
	}
	
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, this->new_sa);
	this->new_sa = NULL;
	
	return SUCCESS;
}

/**
 * implements transaction_t.destroy
 */
static void destroy(private_rekey_ike_sa_t *this)
{
	if (this->new_sa)
	{
		charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager,
													this->new_sa);
	}
	DESTROY_IF(this->message);
	DESTROY_IF(this->connection);
	DESTROY_IF(this->diffie_hellman);
	DESTROY_IF(this->proposal);
	chunk_free(&this->nonce_i);
	chunk_free(&this->nonce_r);
	chunk_free(&this->nonce_s);
	this->randomizer->destroy(this->randomizer);
	free(this);
}

/*
 * Described in header.
 */
rekey_ike_sa_t *rekey_ike_sa_create(ike_sa_t *ike_sa)
{
	private_rekey_ike_sa_t *this = malloc_thing(private_rekey_ike_sa_t);
	
	/* transaction interface functions */
	this->public.transaction.get_request = (status_t(*)(transaction_t*,message_t**))get_request;
	this->public.transaction.get_response = (status_t(*)(transaction_t*,message_t*,message_t**,transaction_t**))get_response;
	this->public.transaction.conclude = (status_t(*)(transaction_t*,message_t*,transaction_t**))conclude;
	this->public.transaction.get_message_id = (u_int32_t(*)(transaction_t*))get_message_id;
	this->public.transaction.requested = (u_int32_t(*)(transaction_t*))requested;
	this->public.transaction.destroy = (void(*)(transaction_t*))destroy;
	
	/* public functions */
	this->public.use_dh_group = (void(*)(rekey_ike_sa_t*,diffie_hellman_group_t))use_dh_group;
	this->public.cancel = (void(*)(rekey_ike_sa_t*))cancel;
	
	/* private data */
	this->ike_sa = ike_sa;
	this->message_id = 0;
	this->message = NULL;
	this->requested = 0;
	this->nonce_i = CHUNK_INITIALIZER;
	this->nonce_r = CHUNK_INITIALIZER;
	this->nonce_s = CHUNK_INITIALIZER;
	this->new_sa = NULL;
	this->lost = FALSE;
	this->connection = NULL;
	this->randomizer = randomizer_create();
	this->diffie_hellman = NULL;
	this->proposal = NULL;
	this->logger = logger_manager->get_logger(logger_manager, IKE_SA);
	
	return &this->public;
}
