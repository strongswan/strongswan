/**
 * @file ike_rekey.c
 *
 * @brief Implementation of the ike_rekey task.
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

#include "ike_rekey.h"

#include <daemon.h>
#include <encoding/payloads/notify_payload.h>
#include <sa/tasks/ike_init.h>
#include <processing/jobs/delete_ike_sa_job.h>
#include <processing/jobs/rekey_ike_sa_job.h>


typedef struct private_ike_rekey_t private_ike_rekey_t;

/**
 * Private members of a ike_rekey_t task.
 */
struct private_ike_rekey_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	ike_rekey_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * New IKE_SA which replaces the current one
	 */
	ike_sa_t *new_sa;
	
	/**
	 * Are we the initiator?
	 */
	bool initiator;
	
	/**
	 * the IKE_INIT task which is reused to simplify rekeying
	 */
	ike_init_t *ike_init;
	
	/**
	 * colliding task detected by the task manager
	 */
	task_t *collision;
};

/**
 * Implementation of task_t.build for initiator
 */
static status_t build_i(private_ike_rekey_t *this, message_t *message)
{
	peer_cfg_t *peer_cfg;
	
	/* create new SA only on first try */
	if (this->new_sa == NULL)
	{
		this->new_sa = charon->ike_sa_manager->checkout_new(charon->ike_sa_manager,
															TRUE);
		
		peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);
		this->new_sa->set_peer_cfg(this->new_sa, peer_cfg);
		this->ike_init = ike_init_create(this->new_sa, TRUE, this->ike_sa);
		this->ike_sa->set_state(this->ike_sa, IKE_REKEYING);
	}
	this->ike_init->task.build(&this->ike_init->task, message);

	return NEED_MORE;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_r(private_ike_rekey_t *this, message_t *message)
{
	peer_cfg_t *peer_cfg;
	iterator_t *iterator;
	child_sa_t *child_sa;
	
	if (this->ike_sa->get_state(this->ike_sa) == IKE_DELETING)
	{
		DBG1(DBG_IKE, "peer initiated rekeying, but we are deleting");
		return NEED_MORE;
	}

	iterator = this->ike_sa->create_child_sa_iterator(this->ike_sa);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		switch (child_sa->get_state(child_sa))
		{
			case CHILD_CREATED:
			case CHILD_REKEYING:
			case CHILD_DELETING:
				/* we do not allow rekeying while we have children in-progress */
				DBG1(DBG_IKE, "peer initiated rekeying, but a child is half-open");
				iterator->destroy(iterator);
				return NEED_MORE;
			default:
				break;
		}
	}
	iterator->destroy(iterator);
	
	this->new_sa = charon->ike_sa_manager->checkout_new(charon->ike_sa_manager,
														FALSE);
	
	peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);
	this->new_sa->set_peer_cfg(this->new_sa, peer_cfg);
	this->ike_init = ike_init_create(this->new_sa, FALSE, this->ike_sa);
	this->ike_init->task.process(&this->ike_init->task, message);
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_rekey_t *this, message_t *message)
{
	if (this->new_sa == NULL)
	{
		/* IKE_SA/a CHILD_SA is in an inacceptable state, deny rekeying */
		message->add_notify(message, TRUE, NO_PROPOSAL_CHOSEN, chunk_empty);
		return SUCCESS;
	}

	if (this->ike_init->task.build(&this->ike_init->task, message) == FAILED)
	{
		return SUCCESS;
	}
	
	this->ike_sa->set_state(this->ike_sa, IKE_REKEYING);
	this->new_sa->set_state(this->new_sa, IKE_ESTABLISHED);
	
	return SUCCESS;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_rekey_t *this, message_t *message)
{
	job_t *job;
	ike_sa_id_t *to_delete;

	switch (this->ike_init->task.process(&this->ike_init->task, message))
	{
		case FAILED:
			/* rekeying failed, fallback to old SA */
			if (!(this->collision &&
				this->collision->get_type(this->collision) == IKE_DELETE))
			{
				job_t *job;
				u_int32_t retry = RETRY_INTERVAL - (random() % RETRY_JITTER);
				job = (job_t*)rekey_ike_sa_job_create(
										this->ike_sa->get_id(this->ike_sa), FALSE);
				DBG1(DBG_IKE, "IKE_SA rekeying failed, "
					 					"trying again in %d seconds", retry);
				this->ike_sa->set_state(this->ike_sa, IKE_ESTABLISHED);
				charon->scheduler->schedule_job(charon->scheduler, job, retry * 1000);
			}
			return SUCCESS;
		case NEED_MORE:
			/* bad dh group, try again */
			this->ike_init->task.migrate(&this->ike_init->task, this->new_sa);
			return NEED_MORE;
		default:
			break;
	}

	this->new_sa->set_state(this->new_sa, IKE_ESTABLISHED);
	to_delete = this->ike_sa->get_id(this->ike_sa);
	
	/* check for collisions */
	if (this->collision &&
		this->collision->get_type(this->collision) == IKE_REKEY)
	{
		chunk_t this_nonce, other_nonce;
		host_t *host;
		private_ike_rekey_t *other = (private_ike_rekey_t*)this->collision;
		
		this_nonce = this->ike_init->get_lower_nonce(this->ike_init);
		other_nonce = other->ike_init->get_lower_nonce(other->ike_init);
		
		/* if we have the lower nonce, delete rekeyed SA. If not, delete
		 * the redundant. */
		if (memcmp(this_nonce.ptr, other_nonce.ptr, 
				   min(this_nonce.len, other_nonce.len)) < 0)
		{
			DBG1(DBG_IKE, "IKE_SA rekey collision won, deleting rekeyed IKE_SA");
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, other->new_sa);
		}
		else
		{
			DBG1(DBG_IKE, "IKE_SA rekey collision lost, deleting redundant IKE_SA");
			/* apply host for a proper delete */
			host = this->ike_sa->get_my_host(this->ike_sa);
			this->new_sa->set_my_host(this->new_sa, host->clone(host));
			host = this->ike_sa->get_other_host(this->ike_sa);
			this->new_sa->set_other_host(this->new_sa, host->clone(host));
			this->ike_sa->set_state(this->ike_sa, IKE_ESTABLISHED);
			to_delete = this->new_sa->get_id(this->new_sa);
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, this->new_sa);
			/* inherit to other->new_sa in destroy() */
			this->new_sa = other->new_sa;
			other->new_sa = NULL;
		}
	}
	
	job = (job_t*)delete_ike_sa_job_create(to_delete, TRUE);
	charon->processor->queue_job(charon->processor, job);	
	
	return SUCCESS;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_ike_rekey_t *this)
{
	return IKE_REKEY;
}

static void collide(private_ike_rekey_t* this, task_t *other)
{
	DESTROY_IF(this->collision);
	this->collision = other;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_rekey_t *this, ike_sa_t *ike_sa)
{
	if (this->ike_init)
	{
		this->ike_init->task.destroy(&this->ike_init->task);
	}
	if (this->new_sa)
	{
		charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager,
													this->new_sa);
	}
	DESTROY_IF(this->collision);

	this->collision = NULL;
	this->ike_sa = ike_sa;
	this->new_sa = NULL;
	this->ike_init = NULL;
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_rekey_t *this)
{
	if (this->new_sa)
	{
		if (this->new_sa->get_state(this->new_sa) == IKE_ESTABLISHED &&
			this->new_sa->inherit(this->new_sa, this->ike_sa) != DESTROY_ME)
		{
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, this->new_sa);
		}
		else
		{
			charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager,
														this->new_sa);
		}
	}
	if (this->ike_init)
	{
		this->ike_init->task.destroy(&this->ike_init->task);
	}
	DESTROY_IF(this->collision);
	free(this);
}

/*
 * Described in header.
 */
ike_rekey_t *ike_rekey_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_rekey_t *this = malloc_thing(private_ike_rekey_t);

	this->public.collide = (void(*)(ike_rekey_t*,task_t*))collide;
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
	this->new_sa = NULL;
	this->ike_init = NULL;
	this->initiator = initiator;
	this->collision = NULL;
	
	return &this->public;
}
