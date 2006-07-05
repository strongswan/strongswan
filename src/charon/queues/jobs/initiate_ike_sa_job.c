/**
 * @file initiate_ike_sa_job.c
 * 
 * @brief Implementation of initiate_ike_sa_job_t.
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


#include <stdlib.h>

#include "initiate_ike_sa_job.h"

#include <daemon.h>
#include <queues/jobs/delete_half_open_ike_sa_job.h>

typedef struct private_initiate_ike_sa_job_t private_initiate_ike_sa_job_t;

/**
 * Private data of an initiate_ike_sa_job_t Object
 */
struct private_initiate_ike_sa_job_t {
	/**
	 * public initiate_ike_sa_job_t interface
	 */
	initiate_ike_sa_job_t public;
	
	/**
	 * associated connection object to initiate
	 */
	connection_t *connection;
	
	/**
	 * logger
	 */
	logger_t *logger;
};

/**
 * Implements initiate_ike_sa_job_t.get_type.
 */
static job_type_t get_type(private_initiate_ike_sa_job_t *this)
{
	return INITIATE_IKE_SA;
}

/**
 * Implementation of job_t.execute.
 */
static status_t execute(private_initiate_ike_sa_job_t *this)
{
	/* Initiatie an IKE_SA:
	 * - is defined by a connection
	 * - create an empty IKE_SA via manager
	 * - call initiate() on this IKE_SA
	 */
	ike_sa_t *ike_sa;
	status_t status;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Creating and checking out IKE SA");
	charon->ike_sa_manager->create_and_checkout(charon->ike_sa_manager, &ike_sa);
	
	status = ike_sa->initiate(ike_sa, this->connection->clone(this->connection));
	if (status != SUCCESS)
	{
		this->logger->log(this->logger, ERROR,
						  "initiation returned %s, going to delete IKE_SA.",
						  mapping_find(status_m, status));
		charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
		return DESTROY_ME;
	}
	
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	return DESTROY_ME;
}

/**
 * Implements job_t.destroy.
 */
static void destroy(private_initiate_ike_sa_job_t *this)
{
	this->connection->destroy(this->connection);
	free(this);
}

/*
 * Described in header
 */
initiate_ike_sa_job_t *initiate_ike_sa_job_create(connection_t *connection)
{
	private_initiate_ike_sa_job_t *this = malloc_thing(private_initiate_ike_sa_job_t);
	
	/* interface functions */
	this->public.job_interface.get_type = (job_type_t (*) (job_t *)) get_type;
	this->public.job_interface.execute = (status_t (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void (*) (job_t *)) destroy;
	
	/* private variables */
	this->connection = connection;
	this->logger = logger_manager->get_logger(logger_manager, WORKER);
	
	return &(this->public);
}
