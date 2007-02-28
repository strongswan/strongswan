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
#include <crypto/diffie_hellman.h>
#include <encoding/payloads/notify_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <sa/tasks/ike_init.h>
#include <queues/jobs/delete_ike_sa_job.h>


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
};

/**
 * Implementation of task_t.build for initiator
 */
static status_t build_i(private_ike_rekey_t *this, message_t *message)
{
	connection_t *connection;
	policy_t *policy;
	ike_sa_id_t *id;
	
	id = ike_sa_id_create(0, 0, TRUE);
	this->new_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, id);
	id->destroy(id);
	
	connection = this->ike_sa->get_connection(this->ike_sa);
	policy = this->ike_sa->get_policy(this->ike_sa);
	this->new_sa->set_connection(this->new_sa, connection);
	this->new_sa->set_policy(this->new_sa, policy);

	this->ike_init = ike_init_create(this->new_sa, TRUE, this->ike_sa);
	this->ike_init->task.build(&this->ike_init->task, message);
	
	this->ike_sa->set_state(this->ike_sa, IKE_REKEYING);

	return NEED_MORE;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_r(private_ike_rekey_t *this, message_t *message)
{
	connection_t *connection;
	policy_t *policy;
	ike_sa_id_t *id;
	
	id = ike_sa_id_create(0, 0, FALSE);
	this->new_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, id);
	id->destroy(id);
	
	connection = this->ike_sa->get_connection(this->ike_sa);
	policy = this->ike_sa->get_policy(this->ike_sa);
	this->new_sa->set_connection(this->new_sa, connection);
	this->new_sa->set_policy(this->new_sa, policy);
	
	this->ike_init = ike_init_create(this->new_sa, FALSE, this->ike_sa);
	this->ike_init->task.process(&this->ike_init->task, message);
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_rekey_t *this, message_t *message)
{
	if (this->ike_init->task.build(&this->ike_init->task, message) == FAILED)
	{
		return SUCCESS;
	}
	
	this->ike_sa->set_state(this->ike_sa, IKE_REKEYING);
	this->new_sa->inherit(this->new_sa, this->ike_sa);
	this->new_sa->set_state(this->new_sa, IKE_ESTABLISHED);
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, this->new_sa);
	this->new_sa = NULL;
	
	return SUCCESS;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_rekey_t *this, message_t *message)
{
	job_t *job;

	if (this->ike_init->task.process(&this->ike_init->task, message) == FAILED)
	{
		return SUCCESS;
	}
	
	this->new_sa->set_state(this->new_sa, IKE_ESTABLISHED);
	this->new_sa->inherit(this->new_sa, this->ike_sa);
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, this->new_sa);
	this->new_sa = NULL;
	
	job = (job_t*)delete_ike_sa_job_create(this->ike_sa->get_id(this->ike_sa),
										   TRUE);
	
	charon->job_queue->add(charon->job_queue, job);
	return SUCCESS;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_ike_rekey_t *this)
{
	return IKE_REKEY;
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

	this->ike_sa = ike_sa;
	this->new_sa = NULL;
	this->ike_init = NULL;
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_rekey_t *this)
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
	free(this);
}

/*
 * Described in header.
 */
ike_rekey_t *ike_rekey_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_rekey_t *this = malloc_thing(private_ike_rekey_t);

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
	
	return &this->public;
}
