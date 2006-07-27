/**
 * @file rekey_ike_sa_job.c
 * 
 * @brief Implementation of rekey_ike_sa_job_t.
 * 
 */

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
 */

#include "rekey_ike_sa_job.h"

#include <daemon.h>


typedef struct private_rekey_ike_sa_job_t private_rekey_ike_sa_job_t;

/**
 * Private data of an rekey_ike_sa_job_t object.
 */
struct private_rekey_ike_sa_job_t {
	/**
	 * Public rekey_ike_sa_job_t interface.
	 */
	rekey_ike_sa_job_t public;
	
	/**
	 * ID of the IKE_SA to rekey
	 */
	ike_sa_id_t *ike_sa_id;
	
	/**
	 * Logger ref
	 */
	logger_t *logger;
};

/**
 * Implementation of job_t.get_type.
 */
static job_type_t get_type(private_rekey_ike_sa_job_t *this)
{
	return REKEY_IKE_SA;
}

/**
 * Implementation of job_t.execute.
 */
static status_t execute(private_rekey_ike_sa_job_t *this)
{
	ike_sa_t *ike_sa;
	
	ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager,
											  this->ike_sa_id);
	if (ike_sa == NULL)
	{
		this->logger->log(this->logger, ERROR,
						  "IKE_SA to rekey not found");
		return DESTROY_ME;
	}
	ike_sa->rekey(ike_sa);
	
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	return DESTROY_ME;
}

/**
 * Implementation of job_t.destroy.
 */
static void destroy(private_rekey_ike_sa_job_t *this)
{
	this->ike_sa_id->destroy(this->ike_sa_id);
	free(this);
}

/*
 * Described in header
 */
rekey_ike_sa_job_t *rekey_ike_sa_job_create(ike_sa_id_t *ike_sa_id)
{
	private_rekey_ike_sa_job_t *this = malloc_thing(private_rekey_ike_sa_job_t);
	
	/* interface functions */
	this->public.job_interface.get_type = (job_type_t (*) (job_t *)) get_type;
	this->public.job_interface.execute = (status_t (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void (*)(job_t*)) destroy;
		
	/* private variables */
	this->ike_sa_id = ike_sa_id->clone(ike_sa_id);
	this->logger = logger_manager->get_logger(logger_manager, WORKER);
	
	return &(this->public);
}
