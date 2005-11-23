/**
 * @file delete_ike_sa_job.h
 * 
 * @brief Job of type DELETE_IKE_SA
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

#include "delete_ike_sa_job.h"

#include <utils/allocator.h>

/**
 * Private data of an delete_ike_sa_job_t Object
 * 
 */
typedef struct private_delete_ike_sa_job_s private_delete_ike_sa_job_t;

struct private_delete_ike_sa_job_s {
	/**
	 * public delete_ike_sa_job_t interface
	 */
	delete_ike_sa_job_t public;
	
	/**
	 * ID of the ike_sa to delete
	 */
	ike_sa_id_t *ike_sa_id;
};


/**
 * Implements delete_ike_sa_job_t's get_type function.
 * See #delete_ike_sa_job_t.get_type for description.
 */
static job_type_t get_type(private_delete_ike_sa_job_t *this)
{
	return DELETE_IKE_SA;
}

/**
 * Implements delete_ike_sa_job_t's get_ike_sa_id function.
 * See #delete_ike_sa_job_t.get_ike_sa_id for description.
 */
static ike_sa_id_t * get_ike_sa_id(private_delete_ike_sa_job_t *this)
{
	return this->ike_sa_id;
}

/**
 * Implements job_t's and delete_ike_sa_job_t's destroy function.
 * See #job_t.destroy or #delete_ike_sa_job_t.destroy for description.
 */
static status_t destroy(job_t *job)
{
	private_delete_ike_sa_job_t *this = (private_delete_ike_sa_job_t *) job;
	this->ike_sa_id->destroy(this->ike_sa_id);
	allocator_free(this);
	return SUCCESS;
}

/*
 * Described in header
 */
delete_ike_sa_job_t *delete_ike_sa_job_create(ike_sa_id_t *ike_sa_id)
{
	private_delete_ike_sa_job_t *this = allocator_alloc_thing(private_delete_ike_sa_job_t);
	if (this == NULL)
	{
		return NULL;
	}
	
	/* interface functions */
	this->public.job_interface.get_type = (job_type_t (*) (job_t *)) get_type;
	/* same as destroy */
	this->public.job_interface.destroy_all = (status_t (*) (job_t *)) destroy;
	this->public.job_interface.destroy = destroy;
	
	/* public functions */
	this->public.get_ike_sa_id = (ike_sa_id_t * (*)(delete_ike_sa_job_t *)) get_ike_sa_id;
	this->public.destroy = (status_t (*)(delete_ike_sa_job_t *)) destroy;
	
	/* private variables */
	if (ike_sa_id->clone(ike_sa_id,&(this->ike_sa_id)) != SUCCESS)
	{
		allocator_free(this);
		return NULL;
	}
	
	return &(this->public);
}
