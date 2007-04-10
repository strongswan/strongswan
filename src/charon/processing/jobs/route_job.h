/**
 * @file route_job.h
 * 
 * @brief Interface of route_job_t.
 */

/*
 * Copyright (C) 2005-2007 Martin Willi
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

#ifndef ROUTE_JOB_H_
#define ROUTE_JOB_H_

typedef struct route_job_t route_job_t;

#include <library.h>
#include <processing/jobs/job.h>
#include <config/peer_cfg.h>

/**
 * @brief Class representing an ROUTE Job.
 *
 * @b Constructors:
 * - route_job_create()
 *
 * @ingroup jobs
 */
struct route_job_t {
	/**
	 * implements job_t interface
	 */
	job_t job_interface;
};

/**
 * @brief Creates a job of type ROUTE.
 * 
 * @param peer_cfg		peer config to use for acquire
 * @param child_cfg		route to install
 * @param route			TRUE to route, FALSE to unroute
 * @return				route_job_t object
 * 
 * @ingroup jobs
 */
route_job_t *route_job_create(peer_cfg_t *peer_cfg, child_cfg_t *child_cfg,
							  bool route);

#endif /*ROUTE_JOB_H_*/
