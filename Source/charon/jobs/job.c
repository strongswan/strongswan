/**
 * @file job.c
 *
 * @brief Job-Class representing a job e.g. in job_queue
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

#include "job.h"

#include "../utils/allocator.h"

mapping_t job_type_m[] = {
	{INCOMING_PACKET, "INCOMING_PACKET"},
	{RETRANSMIT_REQUEST, "RETRANSMIT_REQUEST"},
	{INITIATE_IKE_SA, "INITIATE_IKE_SA"},
	{MAPPING_END, NULL}
};

 /**
 * @brief implements function destroy of job_t
 */
static status_t job_destroy(job_t *job)
{
	allocator_free(job);
	return SUCCESS;
}

/*
 * Creates a job (documented in header-file)
 */
job_t *job_create(job_type_t type, void *assigned_data)
{
	job_t *this = allocator_alloc_thing(job_t);

	this->destroy = job_destroy;

	this->type = type;
	this->assigned_data = assigned_data;

	return this;
}
