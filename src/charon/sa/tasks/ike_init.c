/**
 * @file ike_init.c
 *
 * @brief Implementation of the ike_init task.
 *
 */

/*
 * Copyright (C) 2005-2007 Martin Willi
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

#include "ike_init.h"

#include <string.h>

#include <daemon.h>
#include <crypto/diffie_hellman.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/nonce_payload.h>


typedef struct private_ike_init_t private_ike_init_t;

/**
 * Private members of a ike_init_t task.
 */
struct private_ike_init_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	ike_init_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Are we the initiator?
	 */
	bool initiator;
	
	/**
	 * Connection established by this IKE_SA
	 */
	connection_t *connection;
	
	/**
	 * diffie hellman group to use
	 */
	diffie_hellman_group_t dh_group;
	
	/**
	 * Diffie hellman object used to generate public DH value.
	 */
	diffie_hellman_t *diffie_hellman;
	
	/**
	 * nonce chosen by us
	 */
	chunk_t my_nonce;
	
	/**
	 * nonce chosen by peer
	 */
	chunk_t other_nonce;
	
	/**
	 * Negotiated proposal used for IKE_SA
	 */
	proposal_t *proposal;
	
	/**
	 * Old IKE_SA which gets rekeyed
	 */
	ike_sa_t *old_sa;
	
	/**
	 * cookie received from responder
	 */
	chunk_t cookie;
};

/**
 * build the payloads for the message
 */
static void build_payloads(private_ike_init_t *this, message_t *message)
{
	sa_payload_t *sa_payload;
	ke_payload_t *ke_payload;
	nonce_payload_t *nonce_payload;
	linked_list_t *proposal_list;
	ike_sa_id_t *id;
	proposal_t *proposal;
	iterator_t *iterator;
	
	id = this->ike_sa->get_id(this->ike_sa);
	
	this->connection = this->ike_sa->get_connection(this->ike_sa);

	if (this->initiator)
	{
		proposal_list = this->connection->get_proposals(this->connection);
		if (this->old_sa)
		{	
			/* include SPI of new IKE_SA when we are rekeying */
			iterator = proposal_list->create_iterator(proposal_list, TRUE);
			while (iterator->iterate(iterator, (void**)&proposal))
			{
				proposal->set_spi(proposal, id->get_initiator_spi(id));
			}
			iterator->destroy(iterator);
		}
		
		sa_payload = sa_payload_create_from_proposal_list(proposal_list);
		proposal_list->destroy_offset(proposal_list, offsetof(proposal_t, destroy));
	}
	else
	{
		if (this->old_sa)
		{
			/* include SPI of new IKE_SA when we are rekeying */
			this->proposal->set_spi(this->proposal, id->get_responder_spi(id));
		}
		sa_payload = sa_payload_create_from_proposal(this->proposal);
	}
	message->add_payload(message, (payload_t*)sa_payload);
	
	nonce_payload = nonce_payload_create();
	nonce_payload->set_nonce(nonce_payload, this->my_nonce);
	message->add_payload(message, (payload_t*)nonce_payload);
	
	ke_payload = ke_payload_create_from_diffie_hellman(this->diffie_hellman);
	message->add_payload(message, (payload_t*)ke_payload);
}

/**
 * Read payloads from message
 */
static void process_payloads(private_ike_init_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;

	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		switch (payload->get_type(payload))
		{
			case SECURITY_ASSOCIATION:
			{
				sa_payload_t *sa_payload = (sa_payload_t*)payload;
				linked_list_t *proposal_list;
	
				proposal_list = sa_payload->get_proposals(sa_payload);
				this->proposal = this->connection->select_proposal(
											  this->connection, proposal_list);
				proposal_list->destroy_offset(proposal_list, 
											  offsetof(proposal_t, destroy));
				break;
			}
			case KEY_EXCHANGE:
			{
				ke_payload_t *ke_payload = (ke_payload_t*)payload;
				diffie_hellman_group_t dh_group;
				chunk_t key_data;
				
				dh_group = ke_payload->get_dh_group_number(ke_payload);
				
				if (this->initiator)
				{
					if (dh_group != this->dh_group)
					{
						DBG1(DBG_IKE, "received a DH group not requested (%N)",
							 diffie_hellman_group_names, dh_group);
						break;
					}
				}
				else
				{
					this->dh_group = dh_group;
					if (!this->connection->check_dh_group(this->connection, 
														  dh_group))
					{
						break;
					}
					this->diffie_hellman = diffie_hellman_create(dh_group);
				}
				if (this->diffie_hellman)
				{
					key_data = ke_payload->get_key_exchange_data(ke_payload);
					this->diffie_hellman->set_other_public_value(this->diffie_hellman, key_data);
				}
				break;
			}
			case NONCE:
			{
				nonce_payload_t *nonce_payload = (nonce_payload_t*)payload;
				this->other_nonce = nonce_payload->get_nonce(nonce_payload);
				break;
			}
			default:
				break;
		}
	}
	iterator->destroy(iterator);
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t build_i(private_ike_init_t *this, message_t *message)
{
	randomizer_t *randomizer;
	status_t status;
	
	this->connection = this->ike_sa->get_connection(this->ike_sa);
	SIG(IKE_UP_START, "initiating IKE_SA to %H",
		this->connection->get_other_host(this->connection));
	this->ike_sa->set_state(this->ike_sa, IKE_CONNECTING);

	/* if the DH group is set via use_dh_group(), we already have a DH object */
	if (!this->diffie_hellman)
	{
		this->dh_group = this->connection->get_dh_group(this->connection);
		this->diffie_hellman = diffie_hellman_create(this->dh_group);
		if (this->diffie_hellman == NULL)
		{
			SIG(IKE_UP_FAILED, "configured DH group %N not supported",
				diffie_hellman_group_names, this->dh_group);
			return FAILED;
		}
	}
	
	/* generate nonce only when we are trying the first time */
	if (this->my_nonce.ptr == NULL)
	{
		randomizer = randomizer_create();
		status = randomizer->allocate_pseudo_random_bytes(randomizer, NONCE_SIZE,
														  &this->my_nonce);
		randomizer->destroy(randomizer);
		if (status != SUCCESS)
		{
			SIG(IKE_UP_FAILED, "error generating random nonce value");
			return FAILED;
		}
	}
	
	if (this->cookie.ptr)
	{
		message->add_notify(message, FALSE, COOKIE, this->cookie);
	}
	
	build_payloads(this, message);
	
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_r(private_ike_init_t *this, message_t *message)
{	
	randomizer_t *randomizer;
	
	this->connection = this->ike_sa->get_connection(this->ike_sa);
	SIG(IKE_UP_FAILED, "%H is initiating an IKE_SA",
		message->get_source(message));
	this->ike_sa->set_state(this->ike_sa, IKE_CONNECTING);

	randomizer = randomizer_create();
	if (randomizer->allocate_pseudo_random_bytes(randomizer, NONCE_SIZE,
												 &this->my_nonce) != SUCCESS)
	{
		DBG1(DBG_IKE, "error generating random nonce value");
	}
	randomizer->destroy(randomizer);
	
	process_payloads(this, message);
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_init_t *this, message_t *message)
{
	chunk_t secret;
	status_t status;

	/* check if we have everything we need */
	if (this->proposal == NULL ||
		this->other_nonce.len == 0 || this->my_nonce.len == 0)
	{
		SIG(IKE_UP_FAILED, "received proposals inacceptable");
		message->add_notify(message, TRUE, NO_PROPOSAL_CHOSEN, chunk_empty);
		return FAILED;
	}
	
	if (this->diffie_hellman == NULL ||
		this->diffie_hellman->get_shared_secret(this->diffie_hellman,
												&secret) != SUCCESS)
	{
		chunk_t chunk;
		u_int16_t dh_enc;
		
		SIG(IKE_UP_FAILED, "received inacceptable DH group (%N)",
			 diffie_hellman_group_names, this->dh_group);
		this->dh_group = this->connection->get_dh_group(this->connection);
		dh_enc = htons(this->dh_group);
		chunk.ptr = (u_int8_t*)&dh_enc;
		chunk.len = sizeof(dh_enc);
		message->add_notify(message, TRUE, INVALID_KE_PAYLOAD, chunk);
		DBG1(DBG_IKE, "requesting DH group %N",
			 diffie_hellman_group_names, this->dh_group);
		return FAILED;
	}

	
	if (this->old_sa)
	{
		ike_sa_id_t *id;
		prf_t *prf, *child_prf;
				
		/* Apply SPI if we are rekeying */
		id = this->ike_sa->get_id(this->ike_sa);
		id->set_initiator_spi(id, this->proposal->get_spi(this->proposal));
	
		/* setup crypto keys for the rekeyed SA */
		prf = this->old_sa->get_prf(this->old_sa);
		child_prf = this->old_sa->get_child_prf(this->old_sa);
		status = this->ike_sa->derive_keys(this->ike_sa, this->proposal, secret, 
										   this->other_nonce, this->my_nonce,
										   FALSE, child_prf, prf);
	}
	else
	{
		/* setup crypto keys */
		status =  this->ike_sa->derive_keys(this->ike_sa, this->proposal, secret, 
										    this->other_nonce, this->my_nonce,
										    FALSE, NULL, NULL);
	}
	if (status != SUCCESS)
	{
		SIG(IKE_UP_FAILED, "key derivation failed");
		message->add_notify(message, TRUE, NO_PROPOSAL_CHOSEN, chunk_empty);
		return FAILED;
	}
	
	build_payloads(this, message);

	return SUCCESS;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_init_t *this, message_t *message)
{
	chunk_t secret;
	status_t status;
	iterator_t *iterator;
	payload_t *payload;

	/* check for erronous notifies */
	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		if (payload->get_type(payload) == NOTIFY)
		{
			notify_payload_t *notify = (notify_payload_t*)payload;
			notify_type_t type = notify->get_notify_type(notify);
			
			switch (type)
			{
				case INVALID_KE_PAYLOAD:
				{
					chunk_t data;
					diffie_hellman_group_t old_dh_group;
					
					old_dh_group = this->dh_group;
					data = notify->get_notification_data(notify);
					this->dh_group = ntohs(*((u_int16_t*)data.ptr));
					
					DBG1(DBG_IKE, "peer didn't accept DH group %N, it requested"
						 " %N", diffie_hellman_group_names, old_dh_group,
						 diffie_hellman_group_names, this->dh_group);
					if (!this->connection->check_dh_group(this->connection,
														  this->dh_group))
					{
						SIG(IKE_UP_FAILED, "requested DH group %N not "
							"acceptable, giving up", diffie_hellman_group_names,
							this->dh_group);
						iterator->destroy(iterator);
						return FAILED;
					}
					
					this->ike_sa->reset(this->ike_sa);
					
					iterator->destroy(iterator);
					return NEED_MORE;
				}
				case NAT_DETECTION_SOURCE_IP:
				case NAT_DETECTION_DESTINATION_IP:
					/* skip, handled in ike_natd_t */
					break;
				case COOKIE:
				{
					this->cookie = chunk_clone(notify->get_notification_data(notify));
					this->ike_sa->reset(this->ike_sa);
					iterator->destroy(iterator);
					SIG(IKE_UP_FAILED, "received %N notify",
						notify_type_names, type);
					return NEED_MORE;
				}
				default:
				{
					if (type < 16383)
					{
						SIG(IKE_UP_FAILED, "received %N notify error",
							 notify_type_names, type);
						iterator->destroy(iterator);
						return FAILED;	
					}
					DBG1(DBG_IKE, "received %N notify",
						notify_type_names, type);
					break;
				}
			}
		}
	}
	iterator->destroy(iterator);
	
	process_payloads(this, message);

	/* check if we have everything */
	if (this->proposal == NULL ||
		this->other_nonce.len == 0 || this->my_nonce.len == 0)
	{
		SIG(IKE_UP_FAILED, "peers proposal selection invalid");
		return FAILED;
	}
	
	if (this->diffie_hellman == NULL ||
		this->diffie_hellman->get_shared_secret(this->diffie_hellman,
												&secret) != SUCCESS)
	{
		SIG(IKE_UP_FAILED, "peers DH group selection invalid");
		return FAILED;
	}
	
	/* Apply SPI if we are rekeying */
	if (this->old_sa)
	{
		ike_sa_id_t *id;
		prf_t *prf, *child_prf;
		
		id = this->ike_sa->get_id(this->ike_sa);
		id->set_responder_spi(id, this->proposal->get_spi(this->proposal));
		
		/* setup crypto keys for the rekeyed SA */
		prf = this->old_sa->get_prf(this->old_sa);
		child_prf = this->old_sa->get_child_prf(this->old_sa);
		status = this->ike_sa->derive_keys(this->ike_sa, this->proposal, secret, 
										    this->my_nonce, this->other_nonce,
										    TRUE, child_prf, prf);
	}
	else
	{
		/* setup crypto keys for a new SA */
		status = this->ike_sa->derive_keys(this->ike_sa, this->proposal, secret, 
										   this->my_nonce, this->other_nonce,
										   TRUE, NULL, NULL);
	}
	if (status != SUCCESS)
	{
		SIG(IKE_UP_FAILED, "key derivation failed");
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_ike_init_t *this)
{
	return IKE_INIT;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_init_t *this, ike_sa_t *ike_sa)
{
	DESTROY_IF(this->proposal);
	DESTROY_IF(this->diffie_hellman);
	chunk_free(&this->other_nonce);
	
	this->ike_sa = ike_sa;
	this->proposal = NULL;
	this->diffie_hellman = diffie_hellman_create(this->dh_group);
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_init_t *this)
{
	DESTROY_IF(this->proposal);
	DESTROY_IF(this->diffie_hellman);
	chunk_free(&this->my_nonce);
	chunk_free(&this->other_nonce);
	chunk_free(&this->cookie);
	free(this);
}

/*
 * Described in header.
 */
ike_init_t *ike_init_create(ike_sa_t *ike_sa, bool initiator, ike_sa_t *old_sa)
{
	private_ike_init_t *this = malloc_thing(private_ike_init_t);

	this->public.task.get_type = (task_type_t(*)(task_t*))get_type;
	this->public.task.migrate = (void(*)(task_t*,ike_sa_t*))migrate;
	this->public.task.destroy = (void(*)(task_t*))destroy;
	if (initiator)
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_i;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_i;
	}
	else
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_r;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_r;
	}
	
	this->ike_sa = ike_sa;
	this->initiator = initiator;
	this->dh_group = MODP_NONE;
	this->diffie_hellman = NULL;
	this->my_nonce = chunk_empty;
	this->other_nonce = chunk_empty;
	this->cookie = chunk_empty;
	this->proposal = NULL;
	this->connection = NULL;
	this->old_sa = old_sa;
	
	return &this->public;
}
