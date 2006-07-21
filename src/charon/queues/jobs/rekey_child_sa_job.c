/**
 * @file rekey_child_sa_job.c
 * 
 * @brief Implementation of rekey_child_sa_job_t.
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

#include "rekey_child_sa_job.h"

#include <daemon.h>


typedef struct private_rekey_child_sa_job_t private_rekey_child_sa_job_t;

/**
 * Private data of an rekey_child_sa_job_t object.
 */
struct private_rekey_child_sa_job_t {
	/**
	 * Public rekey_child_sa_job_t interface.
	 */
	rekey_child_sa_job_t public;
	
	/**
	 * reqid of the child to rekey
	 */
	u_int32_t reqid;
	
	/**
	 * protocol of the CHILD_SA (ESP/AH)
	 */
	protocol_id_t protocol;
	
	/**
	 * inbound SPI of the CHILD_SA
	 */
	u_int32_t spi;
	
	/**
	 * Logger ref
	 */
	logger_t *logger;
};

/**
 * Implementation of job_t.get_type.
 */
static job_type_t get_type(private_rekey_child_sa_job_t *this)
{
	return REKEY_CHILD_SA;
}

/**
 * Implementation of job_t.execute.
 */
static status_t execute(private_rekey_child_sa_job_t *this)
{
	ike_sa_t *ike_sa;
	
	ike_sa = charon->ike_sa_manager->checkout_by_child(charon->ike_sa_manager,
													   this->reqid);
	if (ike_sa == NULL)
	{
		this->logger->log(this->logger, ERROR|LEVEL1, 
						  "CHILD_SA not found for rekeying");
		return DESTROY_ME;
	}
	ike_sa->rekey_child_sa(ike_sa, this->protocol, this->spi);
	
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	return DESTROY_ME;
}

/**
 * Implementation of job_t.destroy.
 */
static void destroy(private_rekey_child_sa_job_t *this)
{
	free(this);
}

/*
 * Described in header
 */
rekey_child_sa_job_t *rekey_child_sa_job_create(u_int32_t reqid, 
												protocol_id_t protocol, 
												u_int32_t spi)
{
	private_rekey_child_sa_job_t *this = malloc_thing(private_rekey_child_sa_job_t);
	
	/* interface functions */
	this->public.job_interface.get_type = (job_type_t (*) (job_t *)) get_type;
	this->public.job_interface.execute = (status_t (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void (*)(job_t*)) destroy;
		
	/* private variables */
	this->reqid = reqid;
	this->protocol = protocol;
	this->spi = spi;
	this->logger = logger_manager->get_logger(logger_manager, WORKER);
	
	return &(this->public);
}
