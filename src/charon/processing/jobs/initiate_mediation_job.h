/**
 * @file initiate_mediation_job.h
 * 
 * @brief Interface of initiate_mediation_job_t.
 */

/*
 * Copyright (C) 2007 Tobias Brunner
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

#ifndef INITIATE_MEDIATION_JOB_H_
#define INITIATE_MEDIATION_JOB_H_

typedef struct initiate_mediation_job_t initiate_mediation_job_t;

#include <processing/jobs/job.h>
#include <config/child_cfg.h>
#include <sa/ike_sa_id.h>

/**
 * @brief Class representing a INITIATE_MEDIATION Job.
 * 
 * This job will initiate a mediation on behalf of a mediated connection.
 * If required the mediation connection is established.
 * 
 * @b Constructors:
 * - initiate_mediation_job_create()
 * 
 * @ingroup jobs
 */
struct initiate_mediation_job_t {
	/**
	 * implements job_t interface
	 */
	job_t job_interface;
};

/**
 * @brief Creates a job of type INITIATE_MEDIATION.
 * 
 * @param ike_sa_id		identification of the ike_sa as ike_sa_id_t object (gets cloned)
 * @param child_cfg		child config of the child_sa (gets cloned)
 * @return				job object
 * 
 * @ingroup jobs
 */
initiate_mediation_job_t *initiate_mediation_job_create(ike_sa_id_t *ike_sa_id,
		child_cfg_t *child_cfg);

/**
 * @brief Creates a special job of type INITIATE_MEDIATION that reinitiates a
 * specific connection.
 * 
 * @param mediation_sa_id		identification of the mediation sa (gets cloned)
 * @param mediated_sa_id		identification of the mediated sa (gets cloned)
 * @return						job object
 * 
 * @ingroup jobs
 */
initiate_mediation_job_t *reinitiate_mediation_job_create(ike_sa_id_t *mediation_sa_id,
		ike_sa_id_t *mediated_sa_id);

#endif /*INITIATE_MEDIATION_JOB_H_*/
