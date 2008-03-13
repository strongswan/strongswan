/*
 * Copyright (C) 2007 Tobias Brunner
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
 *
 * $Id$
 */

#include "initiate_mediation_job.h"

#include <sa/ike_sa.h>
#include <daemon.h>


typedef struct private_initiate_mediation_job_t private_initiate_mediation_job_t;

/**
 * Private data of an initiate_mediation_job_t Object
 */
struct private_initiate_mediation_job_t {
	/**
	 * public initiate_mediation_job_t interface
	 */
	initiate_mediation_job_t public;
	
	/**
	 * ID of the IKE_SA of the mediated connection.
	 */
	ike_sa_id_t *mediated_sa_id;
	
	/**
	 * Child config of the CHILD_SA of the mediated connection.
	 */
	child_cfg_t *mediated_child;
	
	/**
	 * ID of the IKE_SA of the mediation connection.
	 */
	ike_sa_id_t *mediation_sa_id;
};

/**
 * Implements job_t.destroy.
 */
static void destroy(private_initiate_mediation_job_t *this)
{
	DESTROY_IF(this->mediation_sa_id);
	DESTROY_IF(this->mediated_sa_id);
	DESTROY_IF(this->mediated_child);
	free(this);
}

/**
 * Callback to handle initiation of mediation connection
 */
static bool initiate_callback(private_initiate_mediation_job_t *this, signal_t signal, level_t level,
					 ike_sa_t *ike_sa, char *format, va_list args)
{
	if (signal == CHILD_UP_SUCCESS)
	{
		/* mediation connection is up */
		this->mediation_sa_id = ike_sa->get_id(ike_sa);
		this->mediation_sa_id = this->mediation_sa_id->clone(this->mediation_sa_id);
		return FALSE;
	}
	return TRUE;
}

/**
 * Implementation of job_t.execute.
 */ 
static void initiate(private_initiate_mediation_job_t *this)
{	/* FIXME: check the logging */
	ike_sa_t *mediated_sa, *mediation_sa;
	peer_cfg_t *mediated_cfg, *mediation_cfg;
	
	mediated_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager,
											  this->mediated_sa_id);
	if (mediated_sa)
	{
		mediated_cfg = mediated_sa->get_peer_cfg(mediated_sa);
		/* get_peer_cfg returns an internal object */
		mediated_cfg->get_ref(mediated_cfg); 
		
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, mediated_sa);
		
		mediation_cfg = mediated_cfg->get_mediated_by(mediated_cfg);
		
		if (charon->connect_manager->check_and_register(charon->connect_manager,
				mediation_cfg->get_my_id(mediation_cfg),
				mediated_cfg->get_peer_id(mediated_cfg),
				this->mediated_sa_id, this->mediated_child))
		{
			mediated_cfg->destroy(mediated_cfg);
			mediation_cfg->destroy(mediation_cfg);
			/* this pointer should still be valid */
			charon->bus->set_sa(charon->bus, mediated_sa);
			DBG1(DBG_IKE, "mediation with the same peer is already in progress, queued");
			destroy(this);
			return;
		}
		/* we need an additional reference because initiate consumes one */
		mediation_cfg->get_ref(mediation_cfg); 

		/* this function call blocks until the connection is up or failed
		 * we do not check the status, but NEED_MORE would be returned on success
		 * because the registered callback returns FALSE then
		 * this->mediation_sa_id is set in the callback */
		charon->controller->initiate(charon->controller,
				mediation_cfg, NULL, (controller_cb_t)initiate_callback, this);
		if (!this->mediation_sa_id)
		{
			DBG1(DBG_JOB, "initiating mediation connection '%s' failed",
					mediation_cfg->get_name(mediation_cfg));
			mediation_cfg->destroy(mediation_cfg);
			mediated_cfg->destroy(mediated_cfg);
			charon->bus->set_sa(charon->bus, mediated_sa);
			SIG(IKE_UP_FAILED, "mediation failed");
			destroy(this);
			return;
		}
		mediation_cfg->destroy(mediation_cfg);

		mediation_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager,
				this->mediation_sa_id);
		
		if (mediation_sa)
		{
			if (mediation_sa->initiate_mediation(mediation_sa, mediated_cfg) != SUCCESS)
			{
				DBG1(DBG_JOB, "initiating mediated connection '%s' failed",
						mediated_cfg->get_name(mediated_cfg));
				mediated_cfg->destroy(mediated_cfg);
				charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, mediation_sa);
				
				charon->bus->set_sa(charon->bus, mediated_sa);
				SIG(IKE_UP_FAILED, "mediation failed");
				destroy(this);
				return;
			}
			
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, mediation_sa);
		}
		
		mediated_cfg->destroy(mediated_cfg);
	}
	destroy(this);
}

/**
 * Implementation of job_t.execute.
 */ 
static void reinitiate(private_initiate_mediation_job_t *this)
{	/* FIXME: check the logging */
	ike_sa_t *mediated_sa, *mediation_sa;
	peer_cfg_t *mediated_cfg;
	
	mediated_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager,
											  this->mediated_sa_id);
	if (mediated_sa)
	{
		mediated_cfg = mediated_sa->get_peer_cfg(mediated_sa);
		mediated_cfg->get_ref(mediated_cfg);
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, mediated_sa);
		
		mediation_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager,
				this->mediation_sa_id);
		if (mediation_sa)
		{
			if (mediation_sa->initiate_mediation(mediation_sa, mediated_cfg) != SUCCESS)
			{
				DBG1(DBG_JOB, "initiating mediated connection '%s' failed",
						mediated_cfg->get_name(mediated_cfg));
				mediated_cfg->destroy(mediated_cfg);
				charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, mediation_sa);
				
				charon->bus->set_sa(charon->bus, mediated_sa);
				SIG(IKE_UP_FAILED, "mediation failed");
				destroy(this);
				return;
			}
			
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, mediation_sa);
		}
		
		mediated_cfg->destroy(mediated_cfg);
	}
	destroy(this);
}

/**
 * Creates an empty job
 */
static private_initiate_mediation_job_t *initiate_mediation_job_create_empty()
{
	private_initiate_mediation_job_t *this = malloc_thing(private_initiate_mediation_job_t);
	
	/* interface functions */
	this->public.job_interface.destroy = (void (*) (job_t *)) destroy;
	
	/* private variables */
	this->mediation_sa_id = NULL;
	this->mediated_sa_id = NULL;
	this->mediated_child = NULL;

	return this;
}

/*
 * Described in header
 */
initiate_mediation_job_t *initiate_mediation_job_create(ike_sa_id_t *ike_sa_id,
		child_cfg_t *child_cfg)
{
	private_initiate_mediation_job_t *this = initiate_mediation_job_create_empty();
	
	this->public.job_interface.execute = (void (*) (job_t *)) initiate;
	
	this->mediated_sa_id = ike_sa_id->clone(ike_sa_id);
	child_cfg->get_ref(child_cfg);
	this->mediated_child = child_cfg;

	return &this->public;
}

/*
 * Described in header
 */
initiate_mediation_job_t *reinitiate_mediation_job_create(ike_sa_id_t *mediation_sa_id,
		ike_sa_id_t *mediated_sa_id)
{
	private_initiate_mediation_job_t *this = initiate_mediation_job_create_empty();
	
	this->public.job_interface.execute = (void (*) (job_t *)) reinitiate;
	
	this->mediation_sa_id = mediation_sa_id->clone(mediation_sa_id);
	this->mediated_sa_id = mediated_sa_id->clone(mediated_sa_id);
	
	return &this->public; 
}
