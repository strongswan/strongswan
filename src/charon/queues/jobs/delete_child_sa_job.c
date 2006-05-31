/**
 * @file delete_child_sa_job.c
 * 
 * @brief Implementation of delete_child_sa_job_t.
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

#include "delete_child_sa_job.h"

#include <daemon.h>


typedef struct private_delete_child_sa_job_t private_delete_child_sa_job_t;

/**
 * Private data of an delete_child_sa_job_t object.
 */
struct private_delete_child_sa_job_t {
	/**
	 * Public delete_child_sa_job_t interface.
	 */
	delete_child_sa_job_t public;
	
	/**
	 * reqid of the sa to delete.
	 */
	u_int32_t reqid;
	
	/**
	 * Logger ref
	 */
	logger_t *logger;
};

/**
 * Implementation of job_t.get_type.
 */
static job_type_t get_type(private_delete_child_sa_job_t *this)
{
	return DELETE_CHILD_SA;
}

/**
 * Implementation of job_t.execute.
 */
static status_t execute(private_delete_child_sa_job_t *this)
{
	ike_sa_t *ike_sa;
	status_t status;
	
	status = charon->ike_sa_manager->checkout_by_reqid(charon->ike_sa_manager, this->reqid, &ike_sa);
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, CONTROL, "CHILD SA didn't exist anymore");
		return DESTROY_ME;
	}
	
	/* TODO */
	
	status = charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	return DESTROY_ME;
}

/**
 * Implementation of job_t.destroy.
 */
static void destroy(private_delete_child_sa_job_t *this)
{
	free(this);
}

/*
 * Described in header
 */
delete_child_sa_job_t *delete_child_sa_job_create(u_int32_t reqid)
{
	private_delete_child_sa_job_t *this = malloc_thing(private_delete_child_sa_job_t);
	
	/* interface functions */
	this->public.job_interface.get_type = (job_type_t (*) (job_t *)) get_type;
	this->public.job_interface.execute = (status_t (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void (*)(job_t*)) destroy;
		
	/* private variables */
	this->reqid = reqid;
	this->logger = logger_manager->get_logger(logger_manager, WORKER);
	
	return &(this->public);
}
