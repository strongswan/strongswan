/**
 * @file child_rekey.c
 *
 * @brief Implementation of the child_rekey task.
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

#include "child_rekey.h"

#include <daemon.h>
#include <crypto/diffie_hellman.h>
#include <encoding/payloads/notify_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <sa/tasks/child_create.h>


typedef struct private_child_rekey_t private_child_rekey_t;

/**
 * Private members of a child_rekey_t task.
 */
struct private_child_rekey_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	child_rekey_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Are we the initiator?
	 */
	bool initiator;
	
	/**
	 * the CHILD_CREATE task which is reused to simplify rekeying
	 */
	child_create_t *child_create;
	
	/**
	 * CHILD_SA which gets rekeyed
	 */
	child_sa_t *child_sa;
	
	/**
	 * redundandt CHILD_SA created simultaneously
	 */
	child_sa_t *simultaneous;
	
	/**
	 * the lowest nonce compared so far
	 */
	chunk_t nonce;
	
	/**
	 * TRUE if we have the lower nonce
	 */
	bool winner;
};

/**
 * get the nonce from a message, return TRUE if it was lower than this->nonce
 */
static bool get_nonce(private_child_rekey_t *this, message_t *message)
{
	nonce_payload_t *payload;
	chunk_t nonce;
	
	payload = (nonce_payload_t*)message->get_payload(message, NONCE);
	if (payload == NULL)
	{
		return FALSE;
	}
	nonce = payload->get_nonce(payload);
	
	if (this->nonce.ptr && memcmp(nonce.ptr, this->nonce.ptr,
								  min(nonce.len, this->nonce.len)) > 0)
	{
		chunk_free(&nonce);
		return FALSE;
	}
	
	chunk_free(&this->nonce);
	this->nonce = nonce;
	return TRUE;
}

/**
 * find a child using the REKEY_SA notify
 */
static void find_child(private_child_rekey_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;
	
	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		notify_payload_t *notify;
		u_int32_t spi;
		protocol_id_t protocol;
		
		if (payload->get_type(payload) != NOTIFY)
		{
			continue;
		}
		
		notify = (notify_payload_t*)payload;
		protocol = notify->get_protocol_id(notify);
		spi = notify->get_spi(notify);
		
		if (protocol != PROTO_ESP && protocol != PROTO_AH)
		{
			continue;
		}
		this->child_sa = this->ike_sa->get_child_sa(this->ike_sa, protocol,
													spi, FALSE);
		break;
			
	}
	iterator->destroy(iterator);
}

#if 0
/**
 * handle a detected simultaneous rekeying situation as responder
 */
static void simultaneous_r(private_child_rekey_t *this, message_t *message)
{
	private_child_rekey_t *other = NULL;
	task_t *task;
	iterator_t *iterator;
	
	this->ike_sa->create_task_iterator(this->ike_sa);
	while (iterator->iterate(iterator, (void**)&task))
	{
		if (task->get_type(task) == CHILD_REKEY)
		{
			other = (private_child_rekey_t*)task;
			break;
		}
	}
	iterator->destroy(iterator);
	
	if (other)
	{
		other->simultaneous = this->child_create->get_child(this->child_create);
	
		if (!get_nonce(other, message))
		{
			/* this wins the race, other lost */
			other->winner = FALSE;
		}
	}
}

/**
 * was there a simultaneous rekeying, did we win the nonce compare?
 */
static bool simultaneous_i(private_child_rekey_t *this, message_t *message)
{
	if (this->winner || get_nonce(this, message))
	{
		/* we have the lower nonce and win */
		return TRUE;
	}
	return FALSE;
}
#endif

/**
 * Implementation of task_t.build for initiator
 */
static status_t build_i(private_child_rekey_t *this, message_t *message)
{	
	notify_payload_t *notify;
	protocol_id_t protocol;
	u_int32_t spi, reqid;
	
	/* we just need the rekey notify ... */
	protocol = this->child_sa->get_protocol(this->child_sa);
	spi = this->child_sa->get_spi(this->child_sa, TRUE);
	notify = notify_payload_create_from_protocol_and_type(protocol, REKEY_SA);
	notify->set_spi(notify, spi);
	message->add_payload(message, (payload_t*)notify);

	/* ... our CHILD_CREATE task does the hard work for us. */
	reqid = this->child_sa->get_reqid(this->child_sa);
	this->child_create->use_reqid(this->child_create, reqid);
	this->child_create->task.build(&this->child_create->task, message);
	get_nonce(this, message);
	
	this->child_sa->set_state(this->child_sa, CHILD_REKEYING);

	return NEED_MORE;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_r(private_child_rekey_t *this, message_t *message)
{
	/* let the CHILD_CREATE task process the message */
	this->child_create->task.process(&this->child_create->task, message);
	get_nonce(this, message);

	find_child(this, message);
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_child_rekey_t *this, message_t *message)
{
	u_int32_t reqid;

	if (this->child_sa == NULL ||
		this->child_sa->get_state(this->child_sa) == CHILD_DELETING)
	{
		message->add_notify(message, TRUE, NO_PROPOSAL_CHOSEN, chunk_empty);
		return SUCCESS;
	}
	
	/* let the CHILD_CREATE task build the response */
	reqid = this->child_sa->get_reqid(this->child_sa);
	this->child_create->use_reqid(this->child_create, reqid);
	this->child_create->task.build(&this->child_create->task, message);
	get_nonce(this, message);

	if (this->child_sa->get_state(this->child_sa) == CHILD_REKEYING)
	{
		/* simultaneous_detected(this); */
	}
	
	this->child_sa->set_state(this->child_sa, CHILD_REKEYING);
	
	return SUCCESS;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_child_rekey_t *this, message_t *message)
{
	protocol_id_t protocol;
	u_int32_t spi;
	
	this->child_create->task.process(&this->child_create->task, message);
	
	/*if (!simultaneous_won(this, message))
	{
		* delete the redundant CHILD_SA, instead of the rekeyed *
		this->child_sa = this->create_child->get_child(this->create_child);
	}*/
	spi = this->child_sa->get_spi(this->child_sa, TRUE);
	protocol = this->child_sa->get_protocol(this->child_sa);
	
	/* TODO: don't delete when rekeying failed */
	if (this->ike_sa->delete_child_sa(this->ike_sa, protocol, spi) != SUCCESS)
	{
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_child_rekey_t *this)
{
	return CHILD_REKEY;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_child_rekey_t *this, ike_sa_t *ike_sa)
{	
	this->child_create->task.migrate(&this->child_create->task, ike_sa);
	chunk_free(&this->nonce);

	this->ike_sa = ike_sa;
	this->winner = TRUE;
	this->simultaneous = NULL;
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_child_rekey_t *this)
{
	this->child_create->task.destroy(&this->child_create->task);
	chunk_free(&this->nonce);
	free(this);
}

/*
 * Described in header.
 */
child_rekey_t *child_rekey_create(ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	private_child_rekey_t *this = malloc_thing(private_child_rekey_t);
	policy_t *policy;

	this->public.task.get_type = (task_type_t(*)(task_t*))get_type;
	this->public.task.migrate = (void(*)(task_t*,ike_sa_t*))migrate;
	this->public.task.destroy = (void(*)(task_t*))destroy;
	if (child_sa != NULL)
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_i;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_i;
		this->initiator = TRUE;
		policy = child_sa->get_policy(child_sa);
		this->child_create = child_create_create(ike_sa, policy);
	}
	else
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_r;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_r;
		this->initiator = FALSE;
		this->child_create = child_create_create(ike_sa, NULL);
	}
	
	this->ike_sa = ike_sa;
	this->child_sa = child_sa;
	this->nonce = chunk_empty;
	this->winner = TRUE;
	this->simultaneous = NULL;
	
	return &this->public;
}
