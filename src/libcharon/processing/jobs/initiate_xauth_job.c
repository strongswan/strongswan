/*
 * Copyright (C) 2007-2008 Tobias Brunner
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

#include "initiate_xauth_job.h"

#include <sa/ike_sa.h>
#include <daemon.h>


typedef struct private_initiate_xauth_job_t private_initiate_xauth_job_t;

/**
 * Private data of an initiate_xauth_job_t Object
 */
struct private_initiate_xauth_job_t {
	/**
	 * public initiate_xauth_job_t interface
	 */
	initiate_xauth_job_t public;

	/**
	 * ID of the IKE_SA of the mediated connection.
	 */
	ike_sa_id_t *ike_sa_id;
};

METHOD(job_t, destroy, void,
	private_initiate_xauth_job_t *this)
{
	DESTROY_IF(this->ike_sa_id);
	free(this);
}

METHOD(job_t, initiate, void,
	private_initiate_xauth_job_t *this)
{
	ike_sa_t *ike_sa;

	ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager,
												   this->ike_sa_id);
	if (ike_sa)
	{
		DBG1(DBG_IKE, "INITIATING XAUTH!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		ike_sa->initiate_xauth(ike_sa);
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	}
	destroy(this);
}

METHOD(job_t, get_priority, job_priority_t,
	private_initiate_xauth_job_t *this)
{
	return JOB_PRIO_MEDIUM;
}

/**
 * Creates an empty job
 */
initiate_xauth_job_t *initiate_xauth_job_create(ike_sa_id_t *ike_sa_id)
{
	private_initiate_xauth_job_t *this;
	INIT(this,
		.public = {
			.job_interface = {
				.get_priority = _get_priority,
				.destroy = _destroy,
				.execute = _initiate,
			},
		},
		.ike_sa_id = ike_sa_id->clone(ike_sa_id),
	);
	return &this->public;
}
