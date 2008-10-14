/*
 * Copyright (C) 2006-2007 Martin Willi
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

#include "ike_delete.h"

#include <daemon.h>
#include <encoding/payloads/delete_payload.h>


typedef struct private_ike_delete_t private_ike_delete_t;

/**file
 * Private members of a ike_delete_t task.
 */
struct private_ike_delete_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	ike_delete_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Are we the initiator?
	 */
	bool initiator;
	
	/**
	 * are we responding to a delete, but have initated our own?
	 */
	bool simultaneous;
};

/**
 * Implementation of task_t.build for initiator
 */
static status_t build_i(private_ike_delete_t *this, message_t *message)
{
	delete_payload_t *delete_payload;

	DBG0(DBG_IKE, "deleting IKE_SA %s[%d] between %H[%D]...%H[%D]",
		 this->ike_sa->get_name(this->ike_sa),
		 this->ike_sa->get_unique_id(this->ike_sa),
		 this->ike_sa->get_my_host(this->ike_sa),
		 this->ike_sa->get_my_id(this->ike_sa),
		 this->ike_sa->get_other_host(this->ike_sa),
		 this->ike_sa->get_other_id(this->ike_sa));

	delete_payload = delete_payload_create(PROTO_IKE);
	message->add_payload(message, (payload_t*)delete_payload);
	this->ike_sa->set_state(this->ike_sa, IKE_DELETING);

	DBG1(DBG_IKE, "sending DELETE for IKE_SA %s[%d]",
		 this->ike_sa->get_name(this->ike_sa),
		 this->ike_sa->get_unique_id(this->ike_sa));

	return NEED_MORE;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_delete_t *this, message_t *message)
{
	/* completed, delete IKE_SA by returning FAILED */
	return FAILED;
}

/**
 * Implementation of task_t.process for responder
 */
static status_t process_r(private_ike_delete_t *this, message_t *message)
{
	/* we don't even scan the payloads, as the message wouldn't have
	 * come so far without being correct */
	DBG1(DBG_IKE, "received DELETE for IKE_SA %s[%d]",
		 this->ike_sa->get_name(this->ike_sa),
		 this->ike_sa->get_unique_id(this->ike_sa));
	DBG1(DBG_IKE, "deleting IKE_SA %s[%d] between %H[%D]...%H[%D]",
		 this->ike_sa->get_name(this->ike_sa),
		 this->ike_sa->get_unique_id(this->ike_sa),
		 this->ike_sa->get_my_host(this->ike_sa),
		 this->ike_sa->get_my_id(this->ike_sa),
		 this->ike_sa->get_other_host(this->ike_sa),
		 this->ike_sa->get_other_id(this->ike_sa));

	switch (this->ike_sa->get_state(this->ike_sa))
	{
		case IKE_ESTABLISHED:
			this->ike_sa->set_state(this->ike_sa, IKE_DELETING);
			this->ike_sa->reestablish(this->ike_sa);
			break;
		case IKE_DELETING:
			this->simultaneous = TRUE;
			/* FALL */
		default:
			this->ike_sa->set_state(this->ike_sa, IKE_DELETING);
			break;
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_delete_t *this, message_t *message)
{
	DBG1(DBG_IKE, "IKE_SA deleted");

	if (this->simultaneous)
	{
		/* wait for peer's response for our delete request, but set a timeout */
		return SUCCESS;
	}
	/* completed, delete IKE_SA by returning FAILED */
	return FAILED;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_ike_delete_t *this)
{
	return IKE_DELETE;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_delete_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
	this->simultaneous = FALSE;
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_delete_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
ike_delete_t *ike_delete_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_delete_t *this = malloc_thing(private_ike_delete_t);

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
	this->simultaneous = FALSE;
	
	return &this->public;
}
