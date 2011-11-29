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

/**
 * @defgroup initiate_xauth_job initiate_xauth_job
 * @{ @ingroup cjobs
 */

#ifndef INITIATE_XAUTH_JOB_H_
#define INITIATE_XAUTH_JOB_H_

typedef struct initiate_xauth_job_t initiate_xauth_job_t;

#include <processing/jobs/job.h>
#include <sa/ike_sa_id.h>

/**
 * Class representing a INITIATE_XAUTH Job.
 *
 * This job will an XAuth authentication exchange.
 */
struct initiate_xauth_job_t {
	/**
	 * implements job_t interface
	 */
	job_t job_interface;
};

/**
 * Creates a job of type INITIATE_XAUTH.
 *
 * @param ike_sa_id_t	identification of the ike_sa as ike_sa_id_t object (gets cloned)
 * @return				job object
 */
initiate_xauth_job_t *initiate_xauth_job_create(ike_sa_id_t *ike_sa_id);

#endif /** INITIATE_XAUTH_JOB_H_ @}*/
