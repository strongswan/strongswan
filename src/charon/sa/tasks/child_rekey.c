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
#include <encoding/payloads/notify_payload.h>
#include <sa/tasks/child_create.h>
#include <sa/tasks/child_delete.h>
#include <processing/jobs/rekey_child_sa_job.h>


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
	 * colliding task, may be delete or rekey
	 */
	task_t *collision;
};

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
		DBG1(DBG_IKE, "unable to rekey, CHILD_SA not found");
		message->add_notify(message, TRUE, NO_PROPOSAL_CHOSEN, chunk_empty);
		return SUCCESS;
	}
	
	/* let the CHILD_CREATE task build the response */
	reqid = this->child_sa->get_reqid(this->child_sa);
	this->child_create->use_reqid(this->child_create, reqid);
	this->child_create->task.build(&this->child_create->task, message);
	
	if (message->get_payload(message, SECURITY_ASSOCIATION) == NULL)
	{
		/* rekeying failed, reuse old child */
		this->child_sa->set_state(this->child_sa, CHILD_INSTALLED);
		return SUCCESS;
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
	child_sa_t *to_delete;
	
	if (this->child_create->task.process(&this->child_create->task, message) == NEED_MORE)
	{
		/* bad DH group while rekeying, try again */
		this->child_create->task.migrate(&this->child_create->task, this->ike_sa);
		return NEED_MORE;
	}
	if (message->get_payload(message, SECURITY_ASSOCIATION) == NULL)
	{
		/* establishing new child failed, reuse old. but not when we
		 * recieved a delete in the meantime */
		if (!(this->collision && 
			  this->collision->get_type(this->collision) == CHILD_DELETE))
		{
			job_t *job;
			u_int32_t retry = RETRY_INTERVAL - (random() % RETRY_JITTER);
			
			job = (job_t*)rekey_child_sa_job_create(
								this->child_sa->get_reqid(this->child_sa),
								this->child_sa->get_protocol(this->child_sa),
								this->child_sa->get_spi(this->child_sa, TRUE));
			DBG1(DBG_IKE, "CHILD_SA rekeying failed, "
				 				"trying again in %d seconds", retry);
			this->child_sa->set_state(this->child_sa, CHILD_INSTALLED);
			charon->scheduler->schedule_job(charon->scheduler, job, retry * 1000);
		}
		return SUCCESS;
	}
	
	to_delete = this->child_sa;
	
	/* check for rekey collisions */
	if (this->collision &&
		this->collision->get_type(this->collision) == CHILD_REKEY)
	{
		chunk_t this_nonce, other_nonce;
		private_child_rekey_t *other = (private_child_rekey_t*)this->collision;
		
		this_nonce = this->child_create->get_lower_nonce(this->child_create);
		other_nonce = other->child_create->get_lower_nonce(other->child_create);
		
		/* if we have the lower nonce, delete rekeyed SA. If not, delete
		 * the redundant. */
		if (memcmp(this_nonce.ptr, other_nonce.ptr, 
				   min(this_nonce.len, other_nonce.len)) < 0)
		{
			DBG1(DBG_IKE, "CHILD_SA rekey collision won, deleting rekeyed child");
		}
		else
		{
			DBG1(DBG_IKE, "CHILD_SA rekey collision lost, deleting redundant child");
			to_delete = this->child_create->get_child(this->child_create);
			if (to_delete == NULL)
			{
				/* ooops, should not happen, fallback */
				to_delete = this->child_sa;
			}
		}
	}
	
	spi = to_delete->get_spi(to_delete, TRUE);
	protocol = to_delete->get_protocol(to_delete);
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
 * Implementation of child_rekey_t.collide
 */
static void collide(private_child_rekey_t *this, task_t *other)
{
	/* the task manager only detects exchange collision, but not if 
	 * the collision is for the same child. we check it here. */
	if (other->get_type(other) == CHILD_REKEY)
	{
		private_child_rekey_t *rekey = (private_child_rekey_t*)other;
		if (rekey == NULL || rekey->child_sa != this->child_sa)
		{
			/* not the same child => no collision */
			return;
		}
	}
	else if (other->get_type(other) == CHILD_DELETE)
	{
		child_delete_t *del = (child_delete_t*)other;
		if (del == NULL || del->get_child(del) != this->child_sa)
		{
			/* not the same child => no collision */ 
			return;
		}
	}
	else
	{
		/* any other task is not critical for collisisions, ignore */
		return;
	}
	DESTROY_IF(this->collision);
	this->collision = other;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_child_rekey_t *this, ike_sa_t *ike_sa)
{	
	this->child_create->task.migrate(&this->child_create->task, ike_sa);
	DESTROY_IF(this->collision);

	this->ike_sa = ike_sa;
	this->collision = NULL;
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_child_rekey_t *this)
{
	this->child_create->task.destroy(&this->child_create->task);
	DESTROY_IF(this->collision);
	free(this);
}

/*
 * Described in header.
 */
child_rekey_t *child_rekey_create(ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	child_cfg_t *config;
	private_child_rekey_t *this = malloc_thing(private_child_rekey_t);

	this->public.collide = (void (*)(child_rekey_t*,task_t*))collide;
	this->public.task.get_type = (task_type_t(*)(task_t*))get_type;
	this->public.task.migrate = (void(*)(task_t*,ike_sa_t*))migrate;
	this->public.task.destroy = (void(*)(task_t*))destroy;
	if (child_sa != NULL)
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_i;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_i;
		this->initiator = TRUE;
		config = child_sa->get_config(child_sa);
		this->child_create = child_create_create(ike_sa, config);
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
	this->collision = NULL;
	
	return &this->public;
}
