/**
 * @file initiate_job.c
 * 
 * @brief Implementation of initiate_job_t.
 * 
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
	 * associated peer config to use for IKE_SA setup
	 */
	peer_cfg_t *peer_cfg;
	
	/**
	 * child config to use for CHILD_SA
	 */
	child_cfg_t *child_cfg;
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
	ike_cfg_t *ike_cfg = this->peer_cfg->get_ike_cfg(this->peer_cfg);
	
	ike_sa = charon->ike_sa_manager->checkout_by_peer(charon->ike_sa_manager,
							ike_cfg->get_my_host(ike_cfg),
							ike_cfg->get_other_host(ike_cfg),
							this->peer_cfg->get_my_id(this->peer_cfg),
							this->peer_cfg->get_other_id(this->peer_cfg));

	if (ike_sa->get_peer_cfg(ike_sa) == NULL)
	{
		ike_sa->set_peer_cfg(ike_sa, this->peer_cfg);
	}

	if (ike_sa->initiate(ike_sa, this->child_cfg) != SUCCESS)
	{
		DBG1(DBG_JOB, "initiation failed, going to delete IKE_SA");
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
	this->peer_cfg->destroy(this->peer_cfg);
	this->child_cfg->destroy(this->child_cfg);
	free(this);
}

/*
 * Described in header
 */
initiate_job_t *initiate_job_create(peer_cfg_t *peer_cfg, child_cfg_t *child_cfg)
{
	private_initiate_job_t *this = malloc_thing(private_initiate_job_t);
	
	/* interface functions */
	this->public.job_interface.get_type = (job_type_t (*) (job_t *)) get_type;
	this->public.job_interface.execute = (status_t (*) (job_t *)) execute;
	this->public.job_interface.destroy = (void (*) (job_t *)) destroy;
	
	/* private variables */
	this->peer_cfg = peer_cfg;
	this->child_cfg = child_cfg;
	
	return &this->public;
}
