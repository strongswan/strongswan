/**
 * @file initiate_ike_sa_job.h
 * 
 * @brief Job of type INITIATE_IKE_SA
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#ifndef INITIATE_IKE_SA_JOB_H_
#define INITIATE_IKE_SA_JOB_H_

#include "../types.h"
#include "job.h"

/**
 * Object representing an INITIATE_IKE_SA Job
 * 
 */
typedef struct initiate_ike_sa_job_s initiate_ike_sa_job_t;

struct initiate_ike_sa_job_s {
	/**
	 * implements job_t interface
	 */
	job_t job_interface;
	
	/**
	 * @brief Returns the currently set configuration name for this job
	 * 	
	 * @warning Returned name is not copied.
	 * 
	 * @param this 	calling initiate_ike_sa_job_t object
	 * @return 		name of the configuration
	 */
	char * (*get_configuration_name) (initiate_ike_sa_job_t *this);

	/**
	 * @brief Destroys an initiate_ike_sa_job_t object.
	 *
	 * @param this 	initiate_ike_sa_job_t object to destroy
	 * @return 		
	 * 				SUCCESS in any case
	 */
	status_t (*destroy) (initiate_ike_sa_job_t *this);
};

/**
 * Creates a job of type INITIATE_IKE_SA
 * 
 * @param configuration_name		name of the configuration to initiate IKE_SA with
 * @return
 * 				- initiate_ike_sa_job_t if successfully
 * 				- NULL if out of ressources or no configuration_name given
 */
initiate_ike_sa_job_t *initiate_ike_sa_job_create(char *configuration_name);

#endif /*INITIATE_IKE_SA_JOB_H_*/
