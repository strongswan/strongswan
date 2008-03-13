/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
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

#include <stdlib.h>

#include "send_dpd_job.h"

#include <sa/ike_sa.h>
#include <daemon.h>


typedef struct private_send_dpd_job_t private_send_dpd_job_t;

/**
 * Private data of an send_dpd_job_t Object
 */
struct private_send_dpd_job_t {
	/**
	 * public send_dpd_job_t interface
	 */
	send_dpd_job_t public;
	
	/**
	 * ID of the IKE_SA which the message belongs to.
	 */
	ike_sa_id_t *ike_sa_id;
};

/**
 * Implements job_t.destroy.
 */
static void destroy(private_send_dpd_job_t *this)
{
	this->ike_sa_id->destroy(this->ike_sa_id);
	free(this);
}

/**
 * Implementation of job_t.execute. 
 */ 
static void execute(private_send_dpd_job_t *this)
{
	ike_sa_t *ike_sa;
	
	ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager,
											  this->ike_sa_id);
	if (ike_sa)
	{
		if (ike_sa->send_dpd(ike_sa) == DESTROY_ME)
		{
			charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
		}
		else
		{
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		}
	}
	destroy(this);
}

/*
 * Described in header
 */
send_dpd_job_t *send_dpd_job_create(ike_sa_id_t *ike_sa_id)
{
	private_send_dpd_job_t *this = malloc_thing(private_send_dpd_job_t);
	
	/* interface functions */
	this->public.job_interface.execute = (void (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void (*) (job_t *)) destroy;
	
	/* private variables */
	this->ike_sa_id = ike_sa_id->clone(ike_sa_id);

	return &this->public;
}
