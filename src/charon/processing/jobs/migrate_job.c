/*
 * Copyright (C) 2006 Martin Willi
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
 * $Id: acquire_job.c 4535 2008-10-31 01:43:23Z andreas $
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
	 * local host address to be used
	 */
	host_t *local;
};

/**
 * Implementation of job_t.destroy.
 */
static void destroy(private_migrate_job_t *this)
{
	DESTROY_IF(this->src_ts);
	DESTROY_IF(this->dst_ts);
	DESTROY_IF(this->local);
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
	if (ike_sa == NULL)
	{
		enumerator_t *enumerator, *children;
		peer_cfg_t *peer_cfg;
		child_cfg_t *found_cfg = NULL;
				
		enumerator = charon->backends->create_peer_cfg_enumerator(charon->backends);
		while (enumerator->enumerate(enumerator, (void**)&peer_cfg))
		{
			child_cfg_t *child_cfg;

			if (peer_cfg->get_ike_version(peer_cfg) != 2)
			{
				continue;
			}

			children = peer_cfg->create_child_cfg_enumerator(peer_cfg);
			while (children->enumerate(children, &child_cfg))
			{
				if (child_cfg->equal_traffic_selectors(child_cfg, TRUE, this->src_ts) &&
					child_cfg->equal_traffic_selectors(child_cfg, FALSE, this->dst_ts))
				{
					found_cfg = child_cfg;
					break;
				}
			}
			children->destroy(children);
			if (found_cfg)
			{
				break;
			}
		}
		enumerator->destroy(enumerator);

		if (found_cfg == NULL)
		{
			DBG1(DBG_JOB, "no matching child config found for policy %R === %R",
						   this->src_ts, this->dst_ts);
			destroy(this);
			return;
		}
		DBG1(DBG_JOB, "found matching child config '%s' for policy %R === %R",
					   found_cfg->get_name(found_cfg),
					   this->src_ts, this->dst_ts);

		ike_sa = charon->ike_sa_manager->checkout_by_config(charon->ike_sa_manager,
															peer_cfg);
		if (ike_sa->get_peer_cfg(ike_sa) == NULL)
		{
			host_t *my_host, *other_host;
			ike_cfg_t *ike_cfg;

			ike_sa->set_peer_cfg(ike_sa, peer_cfg);
			ike_cfg = peer_cfg->get_ike_cfg(peer_cfg);
			my_host = host_create_from_dns(ike_cfg->get_my_addr(ike_cfg), 0, 0);
			other_host = host_create_from_dns(ike_cfg->get_other_addr(ike_cfg), 0, 0);
			ike_sa->set_my_host(ike_sa, my_host);
			ike_sa->set_other_host(ike_sa, other_host);
		}
		if (this->local)
		{
			ike_sa->set_my_host(ike_sa, this->local->clone(this->local));
		}
		/* add a CHILD_SA for 'found_cfg' with a policy that has already been
         * installed in the kernel
         */
	}
	else
	{
		DBG1(DBG_JOB, "found CHILD_SA with reqid {%d}", this->reqid);
		if (this->local)
		{
			ike_sa->set_my_host(ike_sa, this->local);
		}
	}
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	destroy(this);
}

/*
 * Described in header
 */
migrate_job_t *migrate_job_create(u_int32_t reqid,
								  traffic_selector_t *src_ts,
								  traffic_selector_t *dst_ts,
								  policy_dir_t dir,
								  host_t *local)
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
	
	return &this->public;
}
