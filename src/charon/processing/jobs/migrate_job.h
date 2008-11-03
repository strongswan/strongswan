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
 * $Id: acquire_job.h 4535 2008-10-31 01:43:23Z andreas $
 */

/**
 * @defgroup migrate_job migrate_job
 * @{ @ingroup jobs
 */

#ifndef MIGRATE_JOB_H_
#define MIGRATE_JOB_H_

typedef struct migrate_job_t migrate_job_t;

#include <library.h>
#include <utils/host.h>
#include <config/traffic_selector.h>
#include <kernel/kernel_ipsec.h>
#include <processing/jobs/job.h>

/**
 * Class representing a MIGRATE Job.
 * 
 * This job sets a routed CHILD_SA for an existing IPsec policy. 
 */
struct migrate_job_t {
	/**
	 * The job_t interface.
	 */
	job_t job_interface;
};

/**
 * Creates a job of type MIGRATE.
 *
 * We use the reqid or the traffic selectors to find a matching CHILD_SA.
 *
 * @param reqid		reqid of the CHILD_SA to acquire
 * @param src_ts	source traffic selector
 * @param dst_ts	destination traffic selector
 * @param local     local host address to be used in the IKE_SA
 * @return			migrate_job_t object
 */
migrate_job_t *migrate_job_create(u_int32_t reqid,
								  traffic_selector_t *src_ts,
								  traffic_selector_t *dst_ts,
								  policy_dir_t dir,
								  host_t *local);

#endif /* MIGRATE_JOB_H_ @} */
