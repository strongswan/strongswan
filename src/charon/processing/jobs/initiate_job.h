/**
 * @file initiate_job.h
 * 
 * @brief Interface of initiate_job_t.
 */

/*
 * Copyright (C) 2005-2007 Martin Willi
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

#ifndef INITIATE_JOB_H_
#define INITIATE_JOB_H_

typedef struct initiate_job_t initiate_job_t;

#include <library.h>
#include <processing/jobs/job.h>
#include <config/peer_cfg.h>
#include <config/child_cfg.h>

/**
 * @brief Class representing an INITIATE_IKE_SA Job.
 * 
 * This job is created if an IKE_SA should be iniated.
 * 
 * @b Constructors:
 * - initiate_job_create()
 * 
 * @ingroup jobs
 */
struct initiate_job_t {
	/**
	 * implements job_t interface
	 */
	job_t job_interface;
};

/**
 * @brief Creates a job of type INITIATE.
 * 
 * @param peer_cfg		peer configuration to use (if not yet established)
 * @param child_cfg		config to create a CHILD from
 * @return				initiate_job_t object
 * 
 * @ingroup jobs
 */
initiate_job_t *initiate_job_create(peer_cfg_t *peer_cfg, child_cfg_t *child_cfg);

#endif /*INITIATE_JOB_H_*/
