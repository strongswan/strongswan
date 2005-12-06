/**
 * @file delete_established_ike_sa_job.c
 * 
 * @brief Implementation of delete_established_ike_sa_job_t.
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

#include "delete_established_ike_sa_job.h"

#include <utils/allocator.h>


typedef struct private_delete_established_ike_sa_job_t private_delete_established_ike_sa_job_t;

/**
 * Private data of an delete_established_ike_sa_job_t object.
 */
struct private_delete_established_ike_sa_job_t {
	/**
	 * Public delete_established_ike_sa_job_t interface.
	 */
	delete_established_ike_sa_job_t public;
	
	/**
	 * ID of the ike_sa to delete.
	 */
	ike_sa_id_t *ike_sa_id;
};

/**
 * Implementation of job_t.get_type.
 */
static job_type_t get_type(private_delete_established_ike_sa_job_t *this)
{
	return DELETE_ESTABLISHED_IKE_SA;
}

/**
 * Implementation of delete_established_ike_sa_job_t.get_ike_sa_id
 */
static ike_sa_id_t *get_ike_sa_id(private_delete_established_ike_sa_job_t *this)
{
	return this->ike_sa_id;
}

/**
 * Implementation of job_t.destroy.
 */
static void destroy(job_t *job)
{
	private_delete_established_ike_sa_job_t *this = (private_delete_established_ike_sa_job_t *) job;
	this->ike_sa_id->destroy(this->ike_sa_id);
	allocator_free(this);
}

/*
 * Described in header
 */
delete_established_ike_sa_job_t *delete_established_ike_sa_job_create(ike_sa_id_t *ike_sa_id)
{
	private_delete_established_ike_sa_job_t *this = allocator_alloc_thing(private_delete_established_ike_sa_job_t);
	
	/* interface functions */
	this->public.job_interface.get_type = (job_type_t (*) (job_t *)) get_type;
	/* same as destroy */
	this->public.job_interface.destroy_all = (void (*) (job_t *)) destroy;
	this->public.job_interface.destroy = destroy;
	
	/* public functions */
	this->public.get_ike_sa_id = (ike_sa_id_t * (*)(delete_established_ike_sa_job_t *)) get_ike_sa_id;
	this->public.destroy = (void (*)(delete_established_ike_sa_job_t *)) destroy;
	
	/* private variables */
	this->ike_sa_id = ike_sa_id->clone(ike_sa_id);
	
	return &(this->public);
}
