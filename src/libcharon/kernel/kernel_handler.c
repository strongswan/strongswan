/*
 * Copyright (C) 2010 Tobias Brunner
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

#include "kernel_handler.h"

#include <hydra.h>
#include <daemon.h>
#include <processing/jobs/acquire_job.h>
#include <processing/jobs/delete_child_sa_job.h>
#include <processing/jobs/migrate_job.h>
#include <processing/jobs/rekey_child_sa_job.h>
#include <processing/jobs/roam_job.h>
#include <processing/jobs/update_sa_job.h>

typedef struct private_kernel_handler_t private_kernel_handler_t;

/**
 * Private data of a kernel_handler_t object.
 */
struct private_kernel_handler_t {

	/**
	 * Public part of kernel_handler_t object.
	 */
	kernel_handler_t public;

};

METHOD(kernel_listener_t, acquire, bool,
	   private_kernel_handler_t *this, u_int32_t reqid,
	   traffic_selector_t *src_ts, traffic_selector_t *dst_ts)
{
	job_t *job;
	if (src_ts && dst_ts)
	{
		DBG1(DBG_KNL, "creating acquire job for policy %R === %R "
					  "with reqid {%u}", src_ts, dst_ts, reqid);
	}
	else
	{
		DBG1(DBG_KNL, "creating acquire job for policy with reqid {%u}", reqid);
	}
	job = (job_t*)acquire_job_create(reqid, src_ts, dst_ts);
	hydra->processor->queue_job(hydra->processor, job);
	return TRUE;
}

METHOD(kernel_listener_t, expire, bool,
	   private_kernel_handler_t *this, u_int32_t reqid, protocol_id_t protocol,
	   u_int32_t spi, bool hard)
{
	job_t *job;
	DBG1(DBG_KNL, "creating %s job for %N CHILD_SA with SPI %.8x "
				  "and reqid {%u}", hard ? "delete" : "rekey",
				  protocol_id_names, protocol, ntohl(spi), reqid);
	if (hard)
	{
		job = (job_t*)delete_child_sa_job_create(reqid, protocol, spi);
	}
	else
	{
		job = (job_t*)rekey_child_sa_job_create(reqid, protocol, spi);
	}
	hydra->processor->queue_job(hydra->processor, job);
	return TRUE;
}

METHOD(kernel_listener_t, mapping, bool,
	   private_kernel_handler_t *this, u_int32_t reqid, u_int32_t spi,
	   host_t *remote)
{
	job_t *job;
	DBG1(DBG_KNL, "NAT mappings of ESP CHILD_SA with SPI %.8x and "
				  "reqid {%u} changed, queuing update job", ntohl(spi), reqid);
	job = (job_t*)update_sa_job_create(reqid, remote);
	hydra->processor->queue_job(hydra->processor, job);
	return TRUE;
}

METHOD(kernel_listener_t, migrate, bool,
	   private_kernel_handler_t *this, u_int32_t reqid,
	   traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	   policy_dir_t direction, host_t *local, host_t *remote)
{
	job_t *job;
	DBG1(DBG_KNL, "creating migrate job for policy %R === %R %N with "
				  "reqid {%u}", src_ts, dst_ts, policy_dir_names, direction,
				  reqid, local);
	job = (job_t*)migrate_job_create(reqid, src_ts, dst_ts, direction, local,
									 remote);
	hydra->processor->queue_job(hydra->processor, job);
	return TRUE;
}

METHOD(kernel_listener_t, roam, bool,
	   private_kernel_handler_t *this, bool address)
{
	job_t *job;
	job = (job_t*)roam_job_create(address);
	hydra->processor->queue_job(hydra->processor, job);
	return TRUE;
}

METHOD(kernel_handler_t, destroy, void,
	   private_kernel_handler_t *this)
{
	charon->kernel_interface->remove_listener(charon->kernel_interface,
											  &this->public.listener);
	free(this);
}

kernel_handler_t *kernel_handler_create()
{
	private_kernel_handler_t *this;

	INIT(this,
		.public = {
			.listener = {
				.acquire = _acquire,
				.expire = _expire,
				.mapping = _mapping,
				.migrate = _migrate,
				.roam = _roam,
			},
			.destroy = _destroy,
		},
	);

	charon->kernel_interface->add_listener(charon->kernel_interface,
										   &this->public.listener);

	return &this->public;
}

