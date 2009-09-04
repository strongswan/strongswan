/*
 * Copyright (C) 2005-2006 Martin Willi
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

#include "delete_ike_sa_job.h"

#include <daemon.h>

typedef struct private_delete_ike_sa_job_t private_delete_ike_sa_job_t;

/**
 * Private data of an delete_ike_sa_job_t Object
 */
struct private_delete_ike_sa_job_t {
	/**
	 * public delete_ike_sa_job_t interface
	 */
	delete_ike_sa_job_t public;

	/**
	 * ID of the ike_sa to delete
	 */
	ike_sa_id_t *ike_sa_id;

	/**
	 * Should the IKE_SA be deleted if it is in ESTABLISHED state?
	 */
	bool delete_if_established;
};


/**
 * Implements job_t.destroy.
 */
static void destroy(private_delete_ike_sa_job_t *this)
{
	this->ike_sa_id->destroy(this->ike_sa_id);
	free(this);
}

/**
 * Implementation of job_t.execute.
 */
static void execute(private_delete_ike_sa_job_t *this)
{
	ike_sa_t *ike_sa;

	ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager,
											  this->ike_sa_id);
	if (ike_sa)
	{
		if (ike_sa->get_state(ike_sa) == IKE_PASSIVE)
		{
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
			return destroy(this);
		}
		if (this->delete_if_established)
		{
			if (ike_sa->delete(ike_sa) == DESTROY_ME)
			{
				charon->ike_sa_manager->checkin_and_destroy(
												charon->ike_sa_manager, ike_sa);
			}
			else
			{
				charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
			}
		}
		else
		{
			/* destroy only if not ESTABLISHED */
			if (ike_sa->get_state(ike_sa) == IKE_ESTABLISHED)
			{
				charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
			}
			else
			{
				DBG1(DBG_JOB, "deleting half open IKE_SA after timeout");
				charon->ike_sa_manager->checkin_and_destroy(
												charon->ike_sa_manager, ike_sa);
			}
		}
	}
	destroy(this);
}

/*
 * Described in header
 */
delete_ike_sa_job_t *delete_ike_sa_job_create(ike_sa_id_t *ike_sa_id,
											  bool delete_if_established)
{
	private_delete_ike_sa_job_t *this = malloc_thing(private_delete_ike_sa_job_t);

	/* interface functions */
	this->public.job_interface.execute = (void (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void (*)(job_t *)) destroy;;

	/* private variables */
	this->ike_sa_id = ike_sa_id->clone(ike_sa_id);
	this->delete_if_established = delete_if_established;

	return &(this->public);
}
