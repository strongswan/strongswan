/*
 * Copyright (C) 2008 Tobias Brunner
 * Copyright (C) 2005-2008 Martin Willi
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
 *
 * $Id$
 */

#include "ike_init.h"

#include <string.h>

#include <daemon.h>
#include <crypto/diffie_hellman.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/vendor_id_payload.h>

/** maximum retries to do with cookies/other dh groups */
#define MAX_RETRIES 5

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
	 * IKE config to establish
	 */
	ike_cfg_t *config;
	
	/**
	 * diffie hellman group to use
	 */
	diffie_hellman_group_t dh_group;
	
	/**
	 * diffie hellman key exchange
	 */
	diffie_hellman_t *dh;
	
	/**
	 * Keymat derivation (from IKE_SA)
	 */
	keymat_t *keymat;
	
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
	
	/**
	 * retries done so far after failure (cookie or bad dh group)
	 */
	u_int retry;
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
	
	this->config = this->ike_sa->get_ike_cfg(this->ike_sa);

	if (this->initiator)
	{
		proposal_list = this->config->get_proposals(this->config);
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
	ke_payload = ke_payload_create_from_diffie_hellman(this->dh);
	
	if (this->old_sa)
	{	/* payload order differs if we are rekeying */
		message->add_payload(message, (payload_t*)nonce_payload);
		message->add_payload(message, (payload_t*)ke_payload);
	}
	else
	{
		message->add_payload(message, (payload_t*)ke_payload);
		message->add_payload(message, (payload_t*)nonce_payload);
	}
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
				this->proposal = this->config->select_proposal(this->config,
															   proposal_list);
				proposal_list->destroy_offset(proposal_list, 
											  offsetof(proposal_t, destroy));
				break;
			}
			case KEY_EXCHANGE:
			{
				ke_payload_t *ke_payload = (ke_payload_t*)payload;
				
				this->dh_group = ke_payload->get_dh_group_number(ke_payload);
				if (!this->initiator)
				{
					if (this->keymat->set_dh_group(this->keymat, this->dh_group))
					{
						this->dh = this->keymat->get_dh(this->keymat);
					}
				}
				if (this->dh)
				{
					this->dh->set_other_public_value(this->dh,
								ke_payload->get_key_exchange_data(ke_payload));
				}
				break;
			}
			case NONCE:
			{
				nonce_payload_t *nonce_payload = (nonce_payload_t*)payload;

				this->other_nonce = nonce_payload->get_nonce(nonce_payload);
				break;
			}
			case VENDOR_ID:
			{
				vendor_id_payload_t *vendor_id = (vendor_id_payload_t*)payload;
				chunk_t vid = vendor_id->get_data(vendor_id);

				DBG1(DBG_ENC, "received vendor id: %#B", &vid);					
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
	rng_t *rng;
	
	this->config = this->ike_sa->get_ike_cfg(this->ike_sa);
	DBG0(DBG_IKE, "initiating IKE_SA %s[%d] to %H",
		 this->ike_sa->get_name(this->ike_sa),
		 this->ike_sa->get_unique_id(this->ike_sa),
		 this->ike_sa->get_other_host(this->ike_sa));
	this->ike_sa->set_state(this->ike_sa, IKE_CONNECTING);
	
	if (this->retry++ >= MAX_RETRIES)
	{
		DBG1(DBG_IKE, "giving up after %d retries", MAX_RETRIES);
		return FAILED;
	}
	
	/* if the DH group is set via use_dh_group(), we already have a DH object */
	if (!this->dh)
	{
		this->dh_group = this->config->get_dh_group(this->config);
		if (!this->keymat->set_dh_group(this->keymat, this->dh_group))
		{
			DBG1(DBG_IKE, "configured DH group %N not supported",
				diffie_hellman_group_names, this->dh_group);
			return FAILED;
		}
		this->dh = this->keymat->get_dh(this->keymat);
	}
	
	/* generate nonce only when we are trying the first time */
	if (this->my_nonce.ptr == NULL)
	{
		rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
		if (!rng)
		{
			DBG1(DBG_IKE, "error generating nonce");
			return FAILED;
		}
		rng->allocate_bytes(rng, NONCE_SIZE, &this->my_nonce);
		rng->destroy(rng);
	}
	
	if (this->cookie.ptr)
	{
		message->add_notify(message, FALSE, COOKIE, this->cookie);
	}
	
	build_payloads(this, message);

#ifdef ME
	{
		chunk_t connect_id = this->ike_sa->get_connect_id(this->ike_sa);
		if (connect_id.ptr)
		{
			message->add_notify(message, FALSE, ME_CONNECTID, connect_id);
		}
	}
#endif /* ME */
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for responder
 */
static status_t process_r(private_ike_init_t *this, message_t *message)
{	
	rng_t *rng;
	
	this->config = this->ike_sa->get_ike_cfg(this->ike_sa);
	DBG0(DBG_IKE, "%H is initiating an IKE_SA", message->get_source(message));
	this->ike_sa->set_state(this->ike_sa, IKE_CONNECTING);

	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		DBG1(DBG_IKE, "error generating nonce");
		return FAILED;
	}
	rng->allocate_bytes(rng, NONCE_SIZE, &this->my_nonce);
	rng->destroy(rng);
	
#ifdef ME
	{
		chunk_t connect_id = chunk_empty;
		iterator_t *iterator;
		payload_t *payload;
	
		/* check for a ME_CONNECTID notify */
		iterator = message->get_payload_iterator(message);
		while (iterator->iterate(iterator, (void**)&payload))
		{
			if (payload->get_type(payload) == NOTIFY)
			{
				notify_payload_t *notify = (notify_payload_t*)payload;
				notify_type_t type = notify->get_notify_type(notify);
			
				switch (type)
				{
					case ME_CONNECTID:
					{
						chunk_free(&connect_id);
						connect_id = chunk_clone(notify->get_notification_data(notify));
						DBG2(DBG_IKE, "received ME_CONNECTID %#B", &connect_id);
						break;
					}
					default:
					{
						if (type < 16383)
						{
							DBG1(DBG_IKE, "received %N notify error",
								notify_type_names, type);
							break;	
						}
						DBG2(DBG_IKE, "received %N notify",
							notify_type_names, type);
						break;
					}
				}
			}
		}
		iterator->destroy(iterator);
		
		if (connect_id.ptr)
		{
			charon->connect_manager->stop_checks(charon->connect_manager,
				connect_id);
			chunk_free(&connect_id);
		}
	}
#endif /* ME */
	
	process_payloads(this, message);
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_init_t *this, message_t *message)
{
	keymat_t *old_keymat = NULL;
	ike_sa_id_t *id;
	
	/* check if we have everything we need */
	if (this->proposal == NULL ||
		this->other_nonce.len == 0 || this->my_nonce.len == 0)
	{
		DBG1(DBG_IKE, "received proposals inacceptable");
		message->add_notify(message, TRUE, NO_PROPOSAL_CHOSEN, chunk_empty);
		return FAILED;
	}
	
	if (this->dh == NULL ||
		!this->proposal->has_dh_group(this->proposal, this->dh_group))
	{
		u_int16_t group;
		
		if (this->proposal->get_algorithm(this->proposal, DIFFIE_HELLMAN_GROUP,
										  &group, NULL))
		{
			DBG1(DBG_IKE, "DH group %N inacceptable, requesting %N",
				 diffie_hellman_group_names, this->dh_group,
				 diffie_hellman_group_names, group);
			this->dh_group = group;
			group = htons(group);
			message->add_notify(message, FALSE, INVALID_KE_PAYLOAD,
								chunk_from_thing(group));
		}
		else
		{
			DBG1(DBG_IKE, "no acceptable proposal found");
		}
		return FAILED;
	}
	
	id = this->ike_sa->get_id(this->ike_sa);
	if (this->old_sa)
	{	/* rekeying: Apply SPI, include keymat from old SA in key derivation */
		id->set_initiator_spi(id, this->proposal->get_spi(this->proposal));
		old_keymat = this->old_sa->get_keymat(this->old_sa);
	}
	if (!this->keymat->derive_keys(this->keymat, this->proposal, this->other_nonce,
								   this->my_nonce, id, old_keymat))
	{
		DBG1(DBG_IKE, "key derivation failed");
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
	keymat_t *old_keymat = NULL;
	ike_sa_id_t *id;
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
					diffie_hellman_group_t bad_group;
					
					bad_group = this->dh_group;
					data = notify->get_notification_data(notify);
					this->dh_group = ntohs(*((u_int16_t*)data.ptr));
					DBG1(DBG_IKE, "peer didn't accept DH group %N, "
						 "it requested %N", diffie_hellman_group_names,
						 bad_group, diffie_hellman_group_names, this->dh_group);
						 
					if (this->old_sa == NULL)
					{	/* reset the IKE_SA if we are not rekeying */
						this->ike_sa->reset(this->ike_sa);
					}
					
					iterator->destroy(iterator);
					return NEED_MORE;
				}
				case NAT_DETECTION_SOURCE_IP:
				case NAT_DETECTION_DESTINATION_IP:
					/* skip, handled in ike_natd_t */
					break;
				case COOKIE:
				{
					chunk_free(&this->cookie);
					this->cookie = chunk_clone(notify->get_notification_data(notify));
					this->ike_sa->reset(this->ike_sa);
					iterator->destroy(iterator);
					DBG2(DBG_IKE, "received %N notify", notify_type_names, type);
					return NEED_MORE;
				}
				default:
				{
					if (type < 16383)
					{
						DBG1(DBG_IKE, "received %N notify error",
							 notify_type_names, type);
						iterator->destroy(iterator);
						return FAILED;	
					}
					DBG2(DBG_IKE, "received %N notify",
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
		DBG1(DBG_IKE, "peers proposal selection invalid");
		return FAILED;
	}
	
	if (this->dh == NULL ||
		!this->proposal->has_dh_group(this->proposal, this->dh_group))
	{
		DBG1(DBG_IKE, "peer DH group selection invalid");
		return FAILED;
	}
	
	id = this->ike_sa->get_id(this->ike_sa);
	if (this->old_sa)
	{	/* rekeying: Apply SPI, include keymat from old SA in key derivation */
		id->set_responder_spi(id, this->proposal->get_spi(this->proposal));
		old_keymat = this->old_sa->get_keymat(this->old_sa);
	}
	if (!this->keymat->derive_keys(this->keymat, this->proposal, this->my_nonce,
								   this->other_nonce, id, old_keymat))
	{
		DBG1(DBG_IKE, "key derivation failed");
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
 * Implementation of task_t.get_type
 */
static chunk_t get_lower_nonce(private_ike_init_t *this)
{
	if (memcmp(this->my_nonce.ptr, this->other_nonce.ptr,
			   min(this->my_nonce.len, this->other_nonce.len)) < 0)
	{
		return this->my_nonce;
	}
	else
	{
		return this->other_nonce;
	}
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_init_t *this, ike_sa_t *ike_sa)
{
	DESTROY_IF(this->proposal);
	chunk_free(&this->other_nonce);
	
	this->ike_sa = ike_sa;
	this->proposal = NULL;
	this->keymat->set_dh_group(this->keymat, this->dh_group);
	this->dh = this->keymat->get_dh(this->keymat);
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_init_t *this)
{
	DESTROY_IF(this->proposal);
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

	this->public.get_lower_nonce = (chunk_t(*)(ike_init_t*))get_lower_nonce;
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
	this->dh = NULL;
	this->keymat = ike_sa->get_keymat(ike_sa);
	this->my_nonce = chunk_empty;
	this->other_nonce = chunk_empty;
	this->cookie = chunk_empty;
	this->proposal = NULL;
	this->config = NULL;
	this->old_sa = old_sa;
	this->retry = 0;
	
	return &this->public;
}
