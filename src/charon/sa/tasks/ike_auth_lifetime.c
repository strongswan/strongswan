/*
 * Copyright (C) 2007 Martin Willi
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

#include "ike_auth_lifetime.h"

#include <daemon.h>
#include <encoding/payloads/notify_payload.h>


typedef struct private_ike_auth_lifetime_t private_ike_auth_lifetime_t;

/**
 * Private members of a ike_auth_lifetime_t task.
 */
struct private_ike_auth_lifetime_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	ike_auth_lifetime_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
};

/**
 * add the AUTH_LIFETIME notify to the message
 */
static void add_auth_lifetime(private_ike_auth_lifetime_t *this, message_t *message)
{
	chunk_t chunk;
	u_int32_t lifetime;
	
	lifetime = this->ike_sa->get_statistic(this->ike_sa, STAT_REAUTH_TIME);
	if (lifetime)
	{
		chunk = chunk_from_thing(lifetime);
		*(u_int32_t*)chunk.ptr = htonl(lifetime);
		message->add_notify(message, FALSE, AUTH_LIFETIME, chunk);
	}
}

/**
 * read notifys from message and evaluate them
 */
static void process_payloads(private_ike_auth_lifetime_t *this, message_t *message)
{
	iterator_t *iterator;
	payload_t *payload;
	notify_payload_t *notify;
	
	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
	{
		if (payload->get_type(payload) == NOTIFY)
		{
			notify = (notify_payload_t*)payload;
			switch (notify->get_notify_type(notify))
			{
				case AUTH_LIFETIME:					
				{
					chunk_t data = notify->get_notification_data(notify);
					u_int32_t lifetime = ntohl(*(u_int32_t*)data.ptr);
					this->ike_sa->set_auth_lifetime(this->ike_sa, lifetime);
					break;
				}
				default:
					break;
			}
		}
	}
	iterator->destroy(iterator);
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t build_i(private_ike_auth_lifetime_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == INFORMATIONAL)
	{
		add_auth_lifetime(this, message);
		return SUCCESS;
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for responder
 */
static status_t process_r(private_ike_auth_lifetime_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == INFORMATIONAL)
	{
		process_payloads(this, message);
		return SUCCESS;
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_auth_lifetime_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == IKE_AUTH &&
		this->ike_sa->get_state(this->ike_sa) == IKE_ESTABLISHED)
	{
		add_auth_lifetime(this, message);
		return SUCCESS;
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_auth_lifetime_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == IKE_AUTH &&
		this->ike_sa->get_state(this->ike_sa) == IKE_ESTABLISHED)
	{
		process_payloads(this, message);
		return SUCCESS;
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_ike_auth_lifetime_t *this)
{
	return IKE_AUTH_LIFETIME;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_auth_lifetime_t *this, ike_sa_t *ike_sa)
{
	this->ike_sa = ike_sa;
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_auth_lifetime_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
ike_auth_lifetime_t *ike_auth_lifetime_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_auth_lifetime_t *this = malloc_thing(private_ike_auth_lifetime_t);

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
	
	return &this->public;
}

