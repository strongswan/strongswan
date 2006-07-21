/**
 * @file route_job.h
 * 
 * @brief Interface of route_job_t.
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
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

#include <types.h>
#include <queues/jobs/job.h>
#include <config/policies/policy.h>
#include <config/connections/connection.h>


typedef struct route_job_t route_job_t;

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
 * @param connection	connection used for routing
 * @param policy		policy to set up
 * @param route			TRUE to route, FALSE to unroute
 * @return				route_job_t object
 * 
 * @ingroup jobs
 */
route_job_t *route_job_create(connection_t *connection, policy_t *policy, bool route);

#endif /*ROUTE_JOB_H_*/
