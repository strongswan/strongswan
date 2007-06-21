/**
 * @file ike_dpd.c
 *
 * @brief Implementation of the ike_dpd task.
 *
 */

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
 */

#include "ike_dpd.h"

#include <daemon.h>


typedef struct private_ike_dpd_t private_ike_dpd_t;

/**
 * Private members of a ike_dpd_t task.
 */
struct private_ike_dpd_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	ike_dpd_t public;
};

/**
 * Implementation of task_t.build for initiator
 * Implementation of task_t.process for responder
 */
static status_t return_need_more(private_ike_dpd_t *this, message_t *message)
{
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for initiator
 * Implementation of task_t.build for responder
 */
static status_t return_success(private_ike_dpd_t *this, message_t *message)
{
	return SUCCESS;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_ike_dpd_t *this)
{
	return IKE_DPD;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_dpd_t *this, ike_sa_t *ike_sa)
{

}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_dpd_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
ike_dpd_t *ike_dpd_create(bool initiator)
{
	private_ike_dpd_t *this = malloc_thing(private_ike_dpd_t);

	this->public.task.get_type = (task_type_t(*)(task_t*))get_type;
	this->public.task.migrate = (void(*)(task_t*,ike_sa_t*))migrate;
	this->public.task.destroy = (void(*)(task_t*))destroy;
	
	if (initiator)
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))return_need_more;
		this->public.task.process = (status_t(*)(task_t*,message_t*))return_success;
	}
	else
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))return_success;
		this->public.task.process = (status_t(*)(task_t*,message_t*))return_need_more;
	}
	
	return &this->public;
}
