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
 * for more details
 *
 * $Id$
 */

#include "ike_auth.h"

#include <string.h>

#include <daemon.h>
#include <crypto/diffie_hellman.h>
#include <encoding/payloads/id_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/eap_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <sa/authenticators/eap_authenticator.h>



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
	 * EAP authenticator when using EAP
	 */
	eap_authenticator_t *eap_auth;
	
	/**
	 * EAP payload received and ready to process
	 */
	eap_payload_t *eap_payload;
	
	/**
	 * has the peer been authenticated successfully?
	 */
	bool peer_authenticated;
};

/**
 * build the AUTH payload
 */
static status_t build_auth(private_ike_auth_t *this, message_t *message)
{
	authenticator_t *auth;
	auth_payload_t *auth_payload;
	peer_cfg_t *config;
	auth_method_t method;
	status_t status;
	
	/* create own authenticator and add auth payload */
	config = this->ike_sa->get_peer_cfg(this->ike_sa);
	if (!config)
	{
		SIG(IKE_UP_FAILED, "unable to authenticate, no peer config found");
		return FAILED;
	}
	method = config->get_auth_method(config);
	
	auth = authenticator_create(this->ike_sa, method);
	if (auth == NULL)
	{
		SIG(IKE_UP_FAILED, "configured authentication method %N not supported",
			auth_method_names, method);
		return FAILED;
	}
	
	status = auth->build(auth, this->my_packet->get_data(this->my_packet),
						 this->other_nonce, &auth_payload);
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
 * build ID payload(s)
 */
static status_t build_id(private_ike_auth_t *this, message_t *message)
{
	identification_t *me, *other;
	id_payload_t *id;
	peer_cfg_t *config;
	
	me = this->ike_sa->get_my_id(this->ike_sa);
	other = this->ike_sa->get_other_id(this->ike_sa);
	config = this->ike_sa->get_peer_cfg(this->ike_sa);
	
	if (me->contains_wildcards(me))
	{
		me = config->get_my_id(config);
		if (me->contains_wildcards(me))
		{
			SIG(IKE_UP_FAILED, "negotiation of own ID failed");
			return FAILED;
		}
		this->ike_sa->set_my_id(this->ike_sa, me->clone(me));
	}
	
	id = id_payload_create_from_identification(this->initiator ? ID_INITIATOR : ID_RESPONDER, me);
	message->add_payload(message, (payload_t*)id);
	
	/* as initiator, include other ID if it does not contain wildcards */
	if (this->initiator && !other->contains_wildcards(other))
	{
		id = id_payload_create_from_identification(ID_RESPONDER, other);
		message->add_payload(message, (payload_t*)id);
	}
	return SUCCESS;
}

/**
 * process AUTH payload
 */
static status_t process_auth(private_ike_auth_t *this, message_t *message)
{
	auth_payload_t *auth_payload;
	authenticator_t *auth;
	auth_method_t auth_method;
	status_t status;
	
	auth_payload = (auth_payload_t*)message->get_payload(message, AUTHENTICATION);
	
	if (auth_payload == NULL)
	{
		/* AUTH payload is missing, client wants to use EAP authentication */
		return NOT_FOUND;
	}

	auth_method = auth_payload->get_auth_method(auth_payload);
	auth = authenticator_create(this->ike_sa, auth_method);

	if (auth == NULL)
	{
		SIG(IKE_UP_FAILED, "authentication method %N used by %D not "
			"supported", auth_method_names, auth_method,
			this->ike_sa->get_other_id(this->ike_sa));
		return NOT_SUPPORTED;
	}
	status = auth->verify(auth, this->other_packet->get_data(this->other_packet), 
						  this->my_nonce, auth_payload);
	auth->destroy(auth);
	if (status != SUCCESS)
	{
		SIG(IKE_UP_FAILED, "authentication of '%D' with %N failed",
			 this->ike_sa->get_other_id(this->ike_sa), 
			 auth_method_names, auth_method);	
		return FAILED;
	}
	return SUCCESS;
}

/**
 * process ID payload(s)
 */
static status_t process_id(private_ike_auth_t *this, message_t *message)
{
	identification_t *id, *req;
	id_payload_t *idr, *idi;

	idi = (id_payload_t*)message->get_payload(message, ID_INITIATOR);
	idr = (id_payload_t*)message->get_payload(message, ID_RESPONDER);

	if ((this->initiator && idr == NULL) || (!this->initiator && idi == NULL))
	{
		SIG(IKE_UP_FAILED, "ID payload missing in message");
		return FAILED;
	}
	
	if (this->initiator)
	{
		id = idr->get_identification(idr);
		req = this->ike_sa->get_other_id(this->ike_sa);
		if (!id->matches(id, req))
		{
			SIG(IKE_UP_FAILED, "peer ID %D unacceptable, %D required", id, req);
			id->destroy(id);
			return FAILED;
		}
		this->ike_sa->set_other_id(this->ike_sa, id);
	}
	else
	{
		id = idi->get_identification(idi);
		this->ike_sa->set_other_id(this->ike_sa, id);
		if (idr)
		{
			id = idr->get_identification(idr);
			this->ike_sa->set_my_id(this->ike_sa, id);
		}
	}
	return SUCCESS;
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
 * Implementation of task_t.build to create AUTH payload from EAP data
 */
static status_t build_auth_eap(private_ike_auth_t *this, message_t *message)
{
	authenticator_t *auth;
	auth_payload_t *auth_payload;
	
	auth = (authenticator_t*)this->eap_auth;
	if (auth->build(auth, this->my_packet->get_data(this->my_packet),
		this->other_nonce, &auth_payload) != SUCCESS)
	{
		SIG(IKE_UP_FAILED, "generating authentication data failed");
		if (!this->initiator)
		{
			message->add_notify(message, TRUE, AUTHENTICATION_FAILED, chunk_empty);
		}
		return FAILED;
	}
	message->add_payload(message, (payload_t*)auth_payload);
	if (!this->initiator)
	{
		this->ike_sa->set_state(this->ike_sa, IKE_ESTABLISHED);
		SIG(IKE_UP_SUCCESS, "IKE_SA '%s' established between %D[%H]...[%H]%D",
			this->ike_sa->get_name(this->ike_sa),
			this->ike_sa->get_my_id(this->ike_sa), 
			this->ike_sa->get_my_host(this->ike_sa),
			this->ike_sa->get_other_host(this->ike_sa),
			this->ike_sa->get_other_id(this->ike_sa));
		return SUCCESS;
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.process to verify AUTH payload after EAP
 */
static status_t process_auth_eap(private_ike_auth_t *this, message_t *message)
{
	auth_payload_t *auth_payload;
	authenticator_t *auth;

	auth_payload = (auth_payload_t*)message->get_payload(message, AUTHENTICATION);
	this->peer_authenticated = FALSE;
	
	if (auth_payload)
	{
		auth = (authenticator_t*)this->eap_auth;
		if (auth->verify(auth, this->other_packet->get_data(this->other_packet), 
						this->my_nonce, auth_payload) == SUCCESS)
		{
			this->peer_authenticated = TRUE;
		}
	}

	if (!this->peer_authenticated)
	{
		SIG(IKE_UP_FAILED, "authentication of '%D' with %N failed",
			 this->ike_sa->get_other_id(this->ike_sa), 
			 auth_method_names, AUTH_EAP);
		if (this->initiator)
		{
			return FAILED;
		}
		return NEED_MORE;
	}
	if (this->initiator)
	{
		this->ike_sa->set_state(this->ike_sa, IKE_ESTABLISHED);
		SIG(IKE_UP_SUCCESS, "IKE_SA '%s' established between %D[%H]...[%H]%D",
			this->ike_sa->get_name(this->ike_sa),
			this->ike_sa->get_my_id(this->ike_sa), 
			this->ike_sa->get_my_host(this->ike_sa),
			this->ike_sa->get_other_host(this->ike_sa),
			this->ike_sa->get_other_id(this->ike_sa));
		return SUCCESS;
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for EAP exchanges
 */
static status_t process_eap_i(private_ike_auth_t *this, message_t *message)
{
	eap_payload_t *eap;

	eap = (eap_payload_t*)message->get_payload(message, EXTENSIBLE_AUTHENTICATION);
	if (eap == NULL)
	{	
		SIG(IKE_UP_FAILED, "EAP payload missing");
		return FAILED;
	}
	switch (this->eap_auth->process(this->eap_auth, eap, &eap))
	{
		case NEED_MORE:
			this->eap_payload = eap;
			return NEED_MORE;
		case SUCCESS:
			/* EAP exchange completed, now create and process AUTH */
			this->eap_payload = NULL;
			this->public.task.build = (status_t(*)(task_t*,message_t*))build_auth_eap;
			this->public.task.process = (status_t(*)(task_t*,message_t*))process_auth_eap;
			return NEED_MORE;
		default:
			this->eap_payload = NULL;
			SIG(IKE_UP_FAILED, "failed to authenticate against %D using EAP",
				this->ike_sa->get_other_id(this->ike_sa));
			return FAILED;
	}
}

/**
 * Implementation of task_t.process for EAP exchanges
 */
static status_t process_eap_r(private_ike_auth_t *this, message_t *message)
{
	this->eap_payload = (eap_payload_t*)message->get_payload(message, 
													EXTENSIBLE_AUTHENTICATION);
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for EAP exchanges
 */
static status_t build_eap_i(private_ike_auth_t *this, message_t *message)
{
	message->add_payload(message, (payload_t*)this->eap_payload);
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for EAP exchanges
 */
static status_t build_eap_r(private_ike_auth_t *this, message_t *message)
{
	status_t status = NEED_MORE;
	eap_payload_t *eap;
		
	if (this->eap_payload == NULL)
	{
		SIG(IKE_UP_FAILED, "EAP payload missing");
		return FAILED;
	}
	
	switch (this->eap_auth->process(this->eap_auth, this->eap_payload, &eap))
	{
		case NEED_MORE:
			
			break;
		case SUCCESS:
			/* EAP exchange completed, now create and process AUTH */
			this->public.task.build = (status_t(*)(task_t*,message_t*))build_auth_eap;
			this->public.task.process = (status_t(*)(task_t*,message_t*))process_auth_eap;
			break;
		default:
			SIG(IKE_UP_FAILED, "authentication of '%D' with %N failed",
				this->ike_sa->get_other_id(this->ike_sa),
				auth_method_names, AUTH_EAP);
			status = FAILED;
			break;
	}
	message->add_payload(message, (payload_t*)eap);
	return status;
}

/**
 * Implementation of task_t.build for initiator
 */
static status_t build_i(private_ike_auth_t *this, message_t *message)
{
	peer_cfg_t *config;

	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		return collect_my_init_data(this, message);
	}
		
	if (build_id(this, message) != SUCCESS)
	{
		return FAILED;
	}
	
	config = this->ike_sa->get_peer_cfg(this->ike_sa);
	if (config->get_auth_method(config) == AUTH_EAP)
	{
		this->eap_auth = eap_authenticator_create(this->ike_sa);
	}
	else
	{
		if (build_auth(this, message) != SUCCESS)
		{
			return FAILED;
		}
	}

	return NEED_MORE;
}

/**
 * Implementation of task_t.process for responder
 */
static status_t process_r(private_ike_auth_t *this, message_t *message)
{
	peer_cfg_t *config;
	
	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		return collect_other_init_data(this, message);
	}
	
	if (process_id(this, message) != SUCCESS)
	{
		return NEED_MORE;
	}
	
	switch (process_auth(this, message))
	{
		case SUCCESS:
			this->peer_authenticated = TRUE;
			break;
		case NOT_FOUND:
			/* use EAP if no AUTH payload found */
			this->ike_sa->set_condition(this->ike_sa, COND_EAP_AUTHENTICATED, TRUE);
			this->eap_auth = eap_authenticator_create(this->ike_sa);
			break;
		default:
			return NEED_MORE;
	}

	config = charon->backends->get_peer_cfg(charon->backends,
									this->ike_sa->get_my_id(this->ike_sa),
									this->ike_sa->get_other_id(this->ike_sa),
									this->ike_sa->get_other_auth(this->ike_sa));
	if (config)
	{
		this->ike_sa->set_peer_cfg(this->ike_sa, config);
		config->destroy(config);
	}
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_auth_t *this, message_t *message)
{
	peer_cfg_t *config;
	eap_type_t eap_type;
	u_int32_t eap_vendor;
	eap_payload_t *eap_payload;
	status_t status;

	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		return collect_my_init_data(this, message);
	}
	
	if (!this->peer_authenticated && this->eap_auth == NULL)
	{
		/* peer not authenticated, nor does it want to use EAP */
		message->add_notify(message, TRUE, AUTHENTICATION_FAILED, chunk_empty);
		return FAILED;
	}
	
	config = this->ike_sa->get_peer_cfg(this->ike_sa);
	if (config == NULL)
	{
		SIG(IKE_UP_FAILED, "no matching config found for %D...%D",
			this->ike_sa->get_my_id(this->ike_sa),
			this->ike_sa->get_other_id(this->ike_sa));
		message->add_notify(message, TRUE, AUTHENTICATION_FAILED, chunk_empty);
		return FAILED;
	}
	
	if (build_id(this, message) != SUCCESS ||
		build_auth(this, message) != SUCCESS)
	{
		message->add_notify(message, TRUE, AUTHENTICATION_FAILED, chunk_empty);
		return FAILED;
	}
	
	/* use "traditional" authentication if we could authenticate peer */
	if (this->peer_authenticated)
	{
		this->ike_sa->set_state(this->ike_sa, IKE_ESTABLISHED);
		SIG(IKE_UP_SUCCESS, "IKE_SA '%s' established between %D[%H]...[%H]%D",
			this->ike_sa->get_name(this->ike_sa),
			this->ike_sa->get_my_id(this->ike_sa), 
			this->ike_sa->get_my_host(this->ike_sa),
			this->ike_sa->get_other_host(this->ike_sa),
			this->ike_sa->get_other_id(this->ike_sa));
		return SUCCESS;
	}
	
	/* initiate EAP authenitcation */
	eap_type = config->get_eap_type(config, &eap_vendor);
	status = this->eap_auth->initiate(this->eap_auth, eap_type,
									  eap_vendor, &eap_payload);
	message->add_payload(message, (payload_t*)eap_payload);
	if (status != NEED_MORE)
	{
		SIG(IKE_UP_FAILED, "unable to initiate EAP authentication");
		return FAILED;
	}
	
	/* switch to EAP methods */
	this->public.task.build = (status_t(*)(task_t*,message_t*))build_eap_r;
	this->public.task.process = (status_t(*)(task_t*,message_t*))process_eap_r;
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_auth_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;
	peer_cfg_t *config;
	auth_info_t *auth;
	
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
					break;
				case MOBIKE_SUPPORTED:
				case ADDITIONAL_IP4_ADDRESS:
				case ADDITIONAL_IP6_ADDRESS:
					/* handled in ike_mobike task */
					break;
				case AUTH_LIFETIME:
					/* handled in ike_auth_lifetime task */
					break;
				case P2P_ENDPOINT:
					/* handled in ike_p2p task */
					break;
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
	
	if (process_id(this, message) != SUCCESS ||
		process_auth(this, message) != SUCCESS)
	{
		return FAILED;
	}
	
	if (this->eap_auth)
	{
		/* switch to EAP authentication methods */
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_eap_i;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_eap_i;
		return process_eap_i(this, message);
	}
	
	config = this->ike_sa->get_peer_cfg(this->ike_sa);
	auth = this->ike_sa->get_other_auth(this->ike_sa);
	if (!auth->complies(auth, config->get_auth(config)))
	{
		SIG(IKE_UP_FAILED, "authorization of %D for config %s failed",
			this->ike_sa->get_other_id(this->ike_sa), config->get_name(config));
		return FAILED;
	}
	this->ike_sa->set_state(this->ike_sa, IKE_ESTABLISHED);
	SIG(IKE_UP_SUCCESS, "IKE_SA '%s' established between %D[%H]...[%H]%D",
		this->ike_sa->get_name(this->ike_sa),
		this->ike_sa->get_my_id(this->ike_sa),
		this->ike_sa->get_my_host(this->ike_sa),
		this->ike_sa->get_other_host(this->ike_sa),
		this->ike_sa->get_other_id(this->ike_sa));
	return SUCCESS;
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
	if (this->eap_auth)
	{
		this->eap_auth->authenticator_interface.destroy(
									&this->eap_auth->authenticator_interface);
	}
	
	this->my_packet = NULL;
	this->other_packet = NULL;
	this->peer_authenticated = FALSE;
	this->eap_auth = NULL;
	this->eap_payload = NULL;
	this->ike_sa = ike_sa;
	if (this->initiator)
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_i;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_i;
	}
	else
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_r;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_r;
	}
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
	if (this->eap_auth)
	{
		this->eap_auth->authenticator_interface.destroy(
									&this->eap_auth->authenticator_interface);
	}
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
	this->peer_authenticated = FALSE;
	this->eap_auth = NULL;
	this->eap_payload = NULL;
	
	return &this->public;
}
