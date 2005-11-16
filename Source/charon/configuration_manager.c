/**
 * @file configuration.c
 * 
 * @brief Configuration class used to store IKE_SA-configurations.
 * 
 * Object of this type represents a configuration for an IKE_SA and its child_sa's.
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

#include "configuration_manager.h"

#include "types.h"
#include "utils/allocator.h"

/**
 * Private data of an configuration_t object
 */
typedef struct private_configuration_manager_s private_configuration_manager_t;

struct private_configuration_manager_s {

	/**
	 * Public part
	 */
	configuration_manager_t public;

};

static status_t get_remote_host(private_configuration_manager_t *this, char *name, host_t **host)
{
	/* some hard coded users for testing */
	host_t *remote;
	if (strcmp(name, "pinflb30") == 0) {
		remote = host_create(AF_INET, "152.96.193.130", 4500);
		if (remote == NULL) {
			return OUT_OF_RES;	
		}
		return SUCCESS;
	}
	else if (strcmp(name, "pinflb31") == 0) {
		remote = host_create(AF_INET, "152.96.193.131", 4500);
		if (remote == NULL) {
			return OUT_OF_RES;	
		}
		return SUCCESS;
	}
	return NOT_FOUND;
}
	
static status_t get_local_host(private_configuration_manager_t *this, char *name, host_t **host)
{
	/* use default route for now */
	host_t *local;
	local = host_create(AF_INET, "0.0.0.0", 4500);
	if (local == NULL)
	{
		return OUT_OF_RES;	
	}
	*host = local;
	return SUCCESS;
}
	
static status_t get_proposals_for_host(private_configuration_manager_t *this, host_t *host, linked_list_iterator_t *list)
{
	return FAILED;
}
	
static status_t select_proposals_for_host(private_configuration_manager_t *this, host_t *host, linked_list_iterator_t *in, linked_list_iterator_t *out)
{
	return FAILED;
}


/**
 * Implements function destroy of configuration_t.
 * See #configuration_s.destroy for description.
 */
static status_t destroy(private_configuration_manager_t *this)
{
	allocator_free(this);
	return SUCCESS;
}

/*
 * Described in header-file
 */
configuration_manager_t *configuration_manager_create()
{
	private_configuration_manager_t *this = allocator_alloc_thing(private_configuration_manager_t);
	if (this == NULL)
	{
		return NULL;
	}

	/* public functions */
	this->public.destroy = (status_t(*)(configuration_manager_t*))destroy;
	this->public.get_remote_host = (status_t(*)(configuration_manager_t*,char*,host_t**))get_remote_host;
	this->public.get_local_host = (status_t(*)(configuration_manager_t*,char*,host_t**))get_local_host;
	this->public.get_proposals_for_host = (status_t(*)(configuration_manager_t*,host_t*,linked_list_iterator_t*))get_proposals_for_host;
	this->public.select_proposals_for_host = (status_t(*)(configuration_manager_t*,host_t*,linked_list_iterator_t*,linked_list_iterator_t*))select_proposals_for_host;
	

	return (&this->public);
}
