/**
 * @file route_job.c
 * 
 * @brief Implementation of route_job_t.
 * 
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


#include <stdlib.h>

#include "route_job.h"

#include <daemon.h>

typedef struct private_route_job_t private_route_job_t;

/**
 * Private data of an route_job_t Object
 */
struct private_route_job_t {
	/**
	 * public route_job_t interface
	 */
	route_job_t public;
	
	/**
	 * associated connection to route
	 */
	connection_t *connection;
	
	/**
	 * associated policy to route
	 */
	policy_t *policy;
	
	/**
	 * route or unroute?
	 */
	bool route;
	
	/**
	 * logger
	 */
	logger_t *logger;
};

/**
 * Implements route_job_t.get_type.
 */
static job_type_t get_type(private_route_job_t *this)
{
	return ROUTE;
}

/**
 * Implementation of job_t.execute.
 */
static status_t execute(private_route_job_t *this)
{
	ike_sa_t *ike_sa;
	
	ike_sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager,
							this->connection->get_my_host(this->connection),
							this->connection->get_other_host(this->connection),
							this->policy->get_my_id(this->policy),
							this->policy->get_other_id(this->policy));
	if (this->route)
	{
		if (ike_sa->route(ike_sa, this->connection, this->policy) != SUCCESS)
		{
			this->logger->log(this->logger, ERROR,
							  "routing failed");
		}
	}
	else
	{
		if (ike_sa->unroute(ike_sa, this->policy) == DESTROY_ME)
		{
			this->logger->log(this->logger, ERROR,
							  "removing IKE_SA, as last routed CHILD_SA unrouted");
			charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);
			return DESTROY_ME;
		}
	}
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	return DESTROY_ME;
}

/**
 * Implements job_t.destroy.
 */
static void destroy(private_route_job_t *this)
{
	this->connection->destroy(this->connection);
	this->policy->destroy(this->policy);
	free(this);
}

/*
 * Described in header
 */
route_job_t *route_job_create(connection_t *connection, policy_t *policy, bool route)
{
	private_route_job_t *this = malloc_thing(private_route_job_t);
	
	/* interface functions */
	this->public.job_interface.get_type = (job_type_t (*) (job_t *)) get_type;
	this->public.job_interface.execute = (status_t (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void (*) (job_t *)) destroy;
	
	/* private variables */
	this->connection = connection;
	this->policy = policy;
	this->route = route;
	this->logger = logger_manager->get_logger(logger_manager, WORKER);
	
	return &this->public;
}
