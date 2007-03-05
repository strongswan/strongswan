/**
 * @file ike_auth.c
 *
 * @brief Implementation of the ike_auth task.
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

#include "ike_auth.h"

#include <string.h>

#include <daemon.h>
#include <crypto/diffie_hellman.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/nonce_payload.h>


typedef struct private_ike_auth_t private_ike_auth_t;

/**
 * Private members of a ike_auth_t task.
 */
struct private_ike_auth_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	ike_auth_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Are we the initiator?
	 */
	bool initiator;
	
	/**
	 * Nonce chosen by us in ike_init
	 */
	chunk_t my_nonce;
	
	/**
	 * Nonce chosen by peer in ike_init
	 */
	chunk_t other_nonce;
	
	/**
	 * IKE_SA_INIT message sent by us
	 */
	packet_t *my_packet;
	
	/**
	 * IKE_SA_INIT message sent by peer
	 */
	packet_t *other_packet;
	
	/**
	 * authenticator to authenticate us
	 */
	authenticator_t *my_auth;
	
	/**
	 * authenticator to authenticate peer
	 */
	authenticator_t *other_auth;
	
	/**
	 * has the peer been authenticated successfully?
	 */
	bool peer_authenticated;
};

/**
 * build the payloads for the message
 */
static status_t build_payloads(private_ike_auth_t *this, message_t *message)
{
	authenticator_t *auth;
	auth_payload_t *auth_payload;
	id_payload_t *id_payload;
	chunk_t ike_sa_init;
	identification_t *me, *other;
	policy_t *policy;
	auth_method_t method = AUTH_RSA;
	status_t status;
	
	/* add own ID payload */
	me = this->ike_sa->get_my_id(this->ike_sa);
	other = this->ike_sa->get_other_id(this->ike_sa);
	
	/* create own authenticator and add auth payload */
	policy = this->ike_sa->get_policy(this->ike_sa);
	if (!policy)
	{
		SIG(IKE_UP_FAILED, "no acceptable policy found");
		return FAILED;
	}
	
	method = policy->get_auth_method(policy);
	if (me->contains_wildcards(me))
	{
		me = policy->get_my_id(policy);
		if (me->contains_wildcards(me))
		{
			SIG(IKE_UP_FAILED, "negotiation of own ID failed");
			return FAILED;
		}
		this->ike_sa->set_my_id(this->ike_sa, me->clone(me));
	}
		
	id_payload = id_payload_create_from_identification(this->initiator, me);
	message->add_payload(message, (payload_t*)id_payload);
	
	/* as initiator, include other ID if it does not contain wildcards */
	if (this->initiator && !other->contains_wildcards(other))
	{
		id_payload = id_payload_create_from_identification(FALSE, other);
		message->add_payload(message, (payload_t*)id_payload);
	}
	
	auth = authenticator_create(this->ike_sa, method);
	if (auth == NULL)
	{
		SIG(IKE_UP_FAILED, "configured authentication method %N not supported",
			 auth_method_names, method);
		return FAILED;
	}
	
	ike_sa_init = this->my_packet->get_data(this->my_packet);
	status = auth->build(auth, ike_sa_init, this->other_nonce, &auth_payload);
	auth->destroy(auth);
	if (status != SUCCESS)
	{
		SIG(IKE_UP_FAILED, "generating authentication data failed");
		return FAILED;
	}
	message->add_payload(message, (payload_t*)auth_payload);
	
	return SUCCESS;
}

/**
 * process payloads from message
 */
static void process_payloads(private_ike_auth_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;
	payload_type_t type;
	identification_t *idi = NULL, *idr = NULL;
	auth_payload_t *auth_payload = NULL;
	authenticator_t *auth;
	auth_method_t auth_method;
	status_t status;

	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		type = payload->get_type(payload);
		switch (type)
		{
			case ID_INITIATOR:
			{
				id_payload_t *id_payload = (id_payload_t*)payload;
				idi = id_payload->get_identification(id_payload);
				break;			
			}
			case ID_RESPONDER:
			{
				id_payload_t *id_payload = (id_payload_t*)payload;
				idr = id_payload->get_identification(id_payload);
				break;			
			}
			case AUTHENTICATION:
			{
				auth_payload = (auth_payload_t*)payload;
				break;
			}
			default:
				break;
		}
	}
	iterator->destroy(iterator);
	
	/* apply IDs */
	if ((this->initiator && idr == NULL) || (!this->initiator && idi == NULL))
	{
		SIG(IKE_UP_FAILED, "ID payload missing in message");
		DESTROY_IF(idr); DESTROY_IF(idi);
		return;
	}
	
	if (this->initiator)
	{
		this->ike_sa->set_other_id(this->ike_sa, idr);
		DESTROY_IF(idi);
	}
	else
	{
		if (idr)
		{
			this->ike_sa->set_my_id(this->ike_sa, idr);
		}
		this->ike_sa->set_other_id(this->ike_sa, idi);
	}
	
	/* verify auth payload */
	if (auth_payload == NULL)
	{
		SIG(IKE_UP_FAILED, "AUTH payload missing in message");
		return;
	}
		
	auth_method = auth_payload->get_auth_method(auth_payload);
	auth = authenticator_create(this->ike_sa, auth_method);
	if (auth == NULL)
	{
		SIG(IKE_UP_FAILED, "authentication method %N used by %D not "
			"supported", auth_method_names, auth_method,
			this->ike_sa->get_other_id(this->ike_sa));
		return;
	}
	status = auth->verify(auth, this->other_packet->get_data(this->other_packet), 
						  this->my_nonce, auth_payload);
	auth->destroy(auth);
	if (status != SUCCESS)
	{
		SIG(IKE_UP_FAILED, "authentication of %D using %N failed",
			 this->ike_sa->get_other_id(this->ike_sa), 
			 auth_method_names, auth_method);	
		return;
	}
	this->peer_authenticated = TRUE;
}

/**
 * collect the needed information in the IKE_SA_INIT exchange from our message
 */
static status_t collect_my_init_data(private_ike_auth_t *this, message_t *message)
{
	nonce_payload_t *nonce;
	
	/* get the nonce that was generated in ike_init */
	nonce = (nonce_payload_t*)message->get_payload(message, NONCE);
	if (nonce == NULL)
	{
		return FAILED;
	}
	this->my_nonce = nonce->get_nonce(nonce);
	
	/* pre-generate the message, so we can store it for us */
	if (this->ike_sa->generate_message(this->ike_sa, message,
									   &this->my_packet) != SUCCESS)
	{
		return FAILED;
	}
	return NEED_MORE; 
}

/**
 * collect the needed information in the IKE_SA_INIT exchange from others message
 */
static status_t collect_other_init_data(private_ike_auth_t *this, message_t *message)
{
	/* we collect the needed information in the IKE_SA_INIT exchange */
	nonce_payload_t *nonce;
	
	/* get the nonce that was generated in ike_init */
	nonce = (nonce_payload_t*)message->get_payload(message, NONCE);
	if (nonce == NULL)
	{
		return FAILED;
	}
	this->other_nonce = nonce->get_nonce(nonce);
	
	/* pre-generate the message, so we can store it for us */
	this->other_packet = message->get_packet(message);
	return NEED_MORE; 
}

/**
 * Implementation of task_t.build for initiator
 */
static status_t build_i(private_ike_auth_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		return collect_my_init_data(this, message);
	}
	
	if (build_payloads(this, message) == SUCCESS)
	{
		return NEED_MORE;
	}
	return FAILED;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_r(private_ike_auth_t *this, message_t *message)
{	
	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		return collect_other_init_data(this, message);
	}
	
	process_payloads(this, message);
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_auth_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		return collect_my_init_data(this, message);
	}
	
	if (this->peer_authenticated && build_payloads(this, message) == SUCCESS)
	{
		this->ike_sa->set_state(this->ike_sa, IKE_ESTABLISHED);
		SIG(IKE_UP_SUCCESS, "IKE_SA established between %D[%H]...[%H]%D",
			this->ike_sa->get_my_id(this->ike_sa), 
			this->ike_sa->get_my_host(this->ike_sa),
			this->ike_sa->get_other_host(this->ike_sa),
			this->ike_sa->get_other_id(this->ike_sa));
		return SUCCESS;
	}
	message->add_notify(message, TRUE, AUTHENTICATION_FAILED, chunk_empty);
	return FAILED;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_auth_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;
	
	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		return collect_other_init_data(this, message);
	}
	
	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		if (payload->get_type(payload) == NOTIFY)
		{
			notify_payload_t *notify = (notify_payload_t*)payload;
			notify_type_t type = notify->get_notify_type(notify);
			
			switch (type)
			{
				case NO_PROPOSAL_CHOSEN:
				case SINGLE_PAIR_REQUIRED:
				case NO_ADDITIONAL_SAS:
				case INTERNAL_ADDRESS_FAILURE:
				case FAILED_CP_REQUIRED:
				case TS_UNACCEPTABLE:
				case INVALID_SELECTORS:
					/* these are errors, but are not critical as only the
					 * CHILD_SA won't get build, but IKE_SA establishes anyway */
					DBG1(DBG_IKE, "received %N notify, no CHILD_SA built",
						 notify_type_names, type);
					iterator->destroy(iterator);
					return SUCCESS;	
				default:
				{
					if (type < 16383)
					{
						DBG1(DBG_IKE, "received %N notify error",
							 notify_type_names, type);
						iterator->destroy(iterator);
						return FAILED;	
					}
				}
			}
		}
	}
	iterator->destroy(iterator);
	
	process_payloads(this, message);

	if (this->peer_authenticated)
	{
		this->ike_sa->set_state(this->ike_sa, IKE_ESTABLISHED);
		SIG(IKE_UP_SUCCESS, "IKE_SA established between %D[%H]...[%H]%D",
			this->ike_sa->get_my_id(this->ike_sa), 
			this->ike_sa->get_my_host(this->ike_sa),
			this->ike_sa->get_other_host(this->ike_sa),
			this->ike_sa->get_other_id(this->ike_sa));
		return SUCCESS;
	}
	return FAILED;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_ike_auth_t *this)
{
	return IKE_AUTHENTICATE;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_auth_t *this, ike_sa_t *ike_sa)
{
	chunk_free(&this->my_nonce);
	chunk_free(&this->other_nonce);
	DESTROY_IF(this->my_packet);
	DESTROY_IF(this->other_packet);
	DESTROY_IF(this->my_auth);
	DESTROY_IF(this->other_auth);
	this->my_packet = NULL;
	this->other_packet = NULL;
	this->my_auth = NULL;
	this->other_auth = NULL;
	this->peer_authenticated = FALSE;
	this->ike_sa = ike_sa;
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_auth_t *this)
{
	chunk_free(&this->my_nonce);
	chunk_free(&this->other_nonce);
	DESTROY_IF(this->my_packet);
	DESTROY_IF(this->other_packet);
	DESTROY_IF(this->my_auth);
	DESTROY_IF(this->other_auth);
	free(this);
}

/*
 * Described in header.
 */
ike_auth_t *ike_auth_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_auth_t *this = malloc_thing(private_ike_auth_t);

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
	this->my_nonce = chunk_empty;
	this->other_nonce = chunk_empty;
	this->my_packet = NULL;
	this->other_packet = NULL;
	this->my_auth = NULL;
	this->other_auth = NULL;
	this->peer_authenticated = FALSE;
	
	return &this->public;
}
