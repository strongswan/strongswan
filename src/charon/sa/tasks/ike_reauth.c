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

#include "ike_reauth.h"

#include <daemon.h>
#include <sa/tasks/ike_delete.h>


typedef struct private_ike_reauth_t private_ike_reauth_t;

/**
 * Private members of a ike_reauth_t task.
 */
struct private_ike_reauth_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	ike_reauth_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * reused ike_delete task
	 */
	ike_delete_t *ike_delete;
};

/**
 * Implementation of task_t.build for initiator
 */
static status_t build_i(private_ike_reauth_t *this, message_t *message)
{
	return this->ike_delete->task.build(&this->ike_delete->task, message);
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_reauth_t *this, message_t *message)
{
	ike_sa_t *new;
	host_t *host;
	iterator_t *iterator;
	child_sa_t *child_sa;
	
	/* process delete response first */
	this->ike_delete->task.process(&this->ike_delete->task, message);
	
	/* reestablish only if we have children */
	iterator = this->ike_sa->create_child_sa_iterator(this->ike_sa);
	if (iterator->get_count(iterator) == 0)
	{
		DBG1(DBG_IKE, "unable to reestablish IKE_SA, no CHILD_SA to recreate");
		iterator->destroy(iterator);
		return FAILED;
	}
	
	new = charon->ike_sa_manager->checkout_new(charon->ike_sa_manager, TRUE);
	
	new->set_peer_cfg(new, this->ike_sa->get_peer_cfg(this->ike_sa));
	host = this->ike_sa->get_other_host(this->ike_sa);
	new->set_other_host(new, host->clone(host));
	host = this->ike_sa->get_my_host(this->ike_sa);
	new->set_my_host(new, host->clone(host));
	/* if we already have a virtual IP, we reuse it */
	host = this->ike_sa->get_virtual_ip(this->ike_sa, TRUE);
	if (host)
	{
		new->set_virtual_ip(new, TRUE, host);
	}
	
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		switch (child_sa->get_state(child_sa))
		{
			case CHILD_ROUTED:
			{
				/* move routed child directly */
				iterator->remove(iterator);
				new->add_child_sa(new, child_sa);
				break;
			}
			default:
			{
				/* initiate/queue all child SAs */
				child_cfg_t *child_cfg = child_sa->get_config(child_sa);
				child_cfg->get_ref(child_cfg);
				if (new->initiate(new, child_cfg) == DESTROY_ME)
				{
					iterator->destroy(iterator);
					charon->ike_sa_manager->checkin_and_destroy(
										charon->ike_sa_manager, new);
					DBG1(DBG_IKE, "reestablishing IKE_SA failed");
					return FAILED;
				}
				break;
			}
		}
	}
	iterator->destroy(iterator);
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, new);
	
	/* we always return failed to delete the obsolete IKE_SA */
	return FAILED;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_ike_reauth_t *this)
{
	return IKE_REAUTH;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_reauth_t *this, ike_sa_t *ike_sa)
{
	this->ike_delete->task.migrate(&this->ike_delete->task, ike_sa);
	this->ike_sa = ike_sa;
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_reauth_t *this)
{
	this->ike_delete->task.destroy(&this->ike_delete->task);
	free(this);
}

/*
 * Described in header.
 */
ike_reauth_t *ike_reauth_create(ike_sa_t *ike_sa)
{
	private_ike_reauth_t *this = malloc_thing(private_ike_reauth_t);

	this->public.task.get_type = (task_type_t(*)(task_t*))get_type;
	this->public.task.migrate = (void(*)(task_t*,ike_sa_t*))migrate;
	this->public.task.destroy = (void(*)(task_t*))destroy;
	this->public.task.build = (status_t(*)(task_t*,message_t*))build_i;
	this->public.task.process = (status_t(*)(task_t*,message_t*))process_i;
	
	this->ike_sa = ike_sa;
	this->ike_delete = ike_delete_create(ike_sa, TRUE);
	
	return &this->public;
}

