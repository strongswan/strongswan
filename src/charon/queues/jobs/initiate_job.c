/**
 * @file initiate_job.c
 * 
 * @brief Implementation of initiate_job_t.
 * 
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
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


#include <stdlib.h>

#include "initiate_job.h"

#include <daemon.h>

typedef struct private_initiate_job_t private_initiate_job_t;

/**
 * Private data of an initiate_job_t Object
 */
struct private_initiate_job_t {
	/**
	 * public initiate_job_t interface
	 */
	initiate_job_t public;
	
	/**
	 * associated connection to initiate
	 */
	connection_t *connection;
	
	/**
	 * associated policy to initiate
	 */
	policy_t *policy;
	
	/**
	 * logger
	 */
	logger_t *logger;
};

/**
 * Implements initiate_job_t.get_type.
 */
static job_type_t get_type(private_initiate_job_t *this)
{
	return INITIATE;
}

/**
 * Implementation of job_t.execute.
 */
static status_t execute(private_initiate_job_t *this)
{
	ike_sa_t *ike_sa;
	
	ike_sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager,
							this->connection->get_my_host(this->connection),
							this->connection->get_other_host(this->connection),
							this->policy->get_my_id(this->policy),
							this->policy->get_other_id(this->policy));
	
	this->connection->get_ref(this->connection);
	this->policy->get_ref(this->policy);
	if (ike_sa->initiate(ike_sa, this->connection, this->policy) != SUCCESS)
	{
		this->logger->log(this->logger, ERROR,
						  "initiation failed, going to delete IKE_SA");
		charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
		return DESTROY_ME;
	}
	
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	return DESTROY_ME;
}

/**
 * Implements job_t.destroy.
 */
static void destroy(private_initiate_job_t *this)
{
	this->connection->destroy(this->connection);
	this->policy->destroy(this->policy);
	free(this);
}

/*
 * Described in header
 */
initiate_job_t *initiate_job_create(connection_t *connection, policy_t *policy)
{
	private_initiate_job_t *this = malloc_thing(private_initiate_job_t);
	
	/* interface functions */
	this->public.job_interface.get_type = (job_type_t (*) (job_t *)) get_type;
	this->public.job_interface.execute = (status_t (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void (*) (job_t *)) destroy;
	
	/* private variables */
	this->connection = connection;
	this->policy = policy;
	this->logger = logger_manager->get_logger(logger_manager, WORKER);
	
	return &this->public;
}
