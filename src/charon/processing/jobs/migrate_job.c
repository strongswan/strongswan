/*
 * Copyright (C) 2008 Andreas Steffen
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

#include "migrate_job.h"

#include <daemon.h>

#include <config/child_cfg.h>


typedef struct private_migrate_job_t private_migrate_job_t;

/**
 * Private data of a migrate_job_t object.
 */
struct private_migrate_job_t {
	/**
	 * Public migrate_job_t interface.
	 */
	migrate_job_t public;
	
	/**
	 * reqid of the CHILD_SA if it already exists
	 */
	u_int32_t reqid;

	/**
	 * source traffic selector
	 */
	traffic_selector_t *src_ts;

	/**
	 * destination traffic selector
	 */
	traffic_selector_t *dst_ts;

	/**
	 * local host address to be used for IKE
	 */
	host_t *local;

	/**
	 * remote host address to be used for IKE
	 */
	host_t *remote;
};

/**
 * Implementation of job_t.destroy.
 */
static void destroy(private_migrate_job_t *this)
{
	DESTROY_IF(this->src_ts);
	DESTROY_IF(this->dst_ts);
	DESTROY_IF(this->local);
	DESTROY_IF(this->remote);
	free(this);
}

/**
 * Implementation of job_t.execute.
 */
static void execute(private_migrate_job_t *this)
{
	ike_sa_t *ike_sa = NULL;
	
	if (this->reqid)
	{
		ike_sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager,
														this->reqid, TRUE);
	}
	if (ike_sa)
	{
		DBG2(DBG_JOB, "found CHILD_SA with reqid {%d}", this->reqid);
		ike_sa->set_kmaddress(ike_sa, this->local, this->remote);
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	}
	else
	{
		DBG1(DBG_JOB, "no CHILD_SA found with reqid {%d}", this->reqid);
	}
	destroy(this);
}

/*
 * Described in header
 */
migrate_job_t *migrate_job_create(u_int32_t reqid,
								  traffic_selector_t *src_ts,
								  traffic_selector_t *dst_ts,
								  policy_dir_t dir,
								  host_t *local, host_t *remote)
{
	private_migrate_job_t *this = malloc_thing(private_migrate_job_t);
	
	/* interface functions */
	this->public.job_interface.execute = (void (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void (*)(job_t*)) destroy;
	
	/* private variables */
	this->reqid = reqid;
	this->src_ts = (dir == POLICY_OUT) ? src_ts : dst_ts;
	this->dst_ts = (dir == POLICY_OUT) ? dst_ts : src_ts;
	this->local = local;
	this->remote = remote;
	
	return &this->public;
}
