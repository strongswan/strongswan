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
#include "payloads/nonce_payload.h"
#include "payloads/proposal_substructure.h"
#include "payloads/ke_payload.h"
#include "payloads/transform_attribute.h"

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
		remote = host_create(AF_INET, "152.96.193.130", 500);
		if (remote == NULL) {
			return OUT_OF_RES;	
		}
		*host = remote;
		return SUCCESS;
	}
	else if (strcmp(name, "pinflb31") == 0) {
		remote = host_create(AF_INET, "152.96.193.131", 500);
		if (remote == NULL) {
			return OUT_OF_RES;	
		}
		*host = remote;
		return SUCCESS;
	}
	return NOT_FOUND;
}
	
static status_t get_local_host(private_configuration_manager_t *this, char *name, host_t **host)
{
	/* use default route for now */
	host_t *local;
	local = host_create(AF_INET, "0.0.0.0", 0);
	if (local == NULL)
	{
		return OUT_OF_RES;	
	}
	*host = local;
	return SUCCESS;
}
	
static status_t get_proposals_for_host(private_configuration_manager_t *this, host_t *host, linked_list_iterator_t *iterator)
{
	/* use a default proposal:
	 * - ENCR_AES_CBC 128Bit
	 * - PRF_HMAC_SHA1 128Bit
	 * - AUTH_HMAC_SHA1_96 96Bit
	 * - MODP_1024_BIT
	 */
	proposal_substructure_t *proposal;
	transform_substructure_t *transform;
	transform_attribute_t *attribute;
	status_t status;
	
	proposal = proposal_substructure_create();
	if (proposal == NULL)
	{
		return OUT_OF_RES;
	}
	
	/* 
	 * Encryption Algorithm 
	 */
	transform = transform_substructure_create();
	if (transform == NULL)
	{
		proposal->destroy(proposal);
		return OUT_OF_RES;
	}
	status = proposal->add_transform_substructure(proposal, transform);
	if (status != SUCCESS)
	{
		proposal->destroy(proposal);
		return OUT_OF_RES;
	}
	transform->set_is_last_transform(transform, FALSE);
	transform->set_transform_type(transform, ENCRYPTION_ALGORITHM);
	transform->set_transform_id(transform, ENCR_AES_CBC);
	
	attribute = transform_attribute_create();
	if (attribute == NULL)
	{
		proposal->destroy(proposal);
		return OUT_OF_RES;
	}
	status = transform->add_transform_attribute(transform, attribute);
	if (status != SUCCESS)
	{
		proposal->destroy(proposal);
		return OUT_OF_RES;
	}
	attribute->set_attribute_type(attribute, KEY_LENGTH);
	attribute->set_value(attribute, 16);
	
 	/* 
 	 * Pseudo-random Function
 	 */
 	transform = transform_substructure_create();
	if (transform == NULL)
	{
		proposal->destroy(proposal);
		return OUT_OF_RES;
	}
	status = proposal->add_transform_substructure(proposal, transform);
	if (status != SUCCESS)
	{
		proposal->destroy(proposal);
		return OUT_OF_RES;
	}
	transform->set_is_last_transform(transform, FALSE);
	transform->set_transform_type(transform, PSEUDO_RANDOM_FUNCTION);
	transform->set_transform_id(transform, PRF_HMAC_SHA1);
	
	attribute = transform_attribute_create();
	if (attribute == NULL)
	{		
		proposal->destroy(proposal);
		return OUT_OF_RES;
	}
	status = transform->add_transform_attribute(transform, attribute);
	if (status != SUCCESS)
	{
		proposal->destroy(proposal);
		return OUT_OF_RES;
	}
	attribute->set_attribute_type(attribute, KEY_LENGTH);
	attribute->set_value(attribute, 16);

 	
 	/* 
 	 * Integrity Algorithm 
 	 */
 	transform = transform_substructure_create();
	if (transform == NULL)
	{
		proposal->destroy(proposal);
		return OUT_OF_RES;
	}
	status = proposal->add_transform_substructure(proposal, transform);
	if (status != SUCCESS)
	{
		proposal->destroy(proposal);
		return OUT_OF_RES;
	}
	transform->set_is_last_transform(transform, FALSE);
	transform->set_transform_type(transform, INTEGRITIY_ALGORITHM);
	transform->set_transform_id(transform, AUTH_HMAC_SHA1_96);
	
	attribute = transform_attribute_create();
	if (attribute == NULL)
	{		
		proposal->destroy(proposal);
		return OUT_OF_RES;
	}
	status = transform->add_transform_attribute(transform, attribute);
	if (status != SUCCESS)
	{
		proposal->destroy(proposal);
		return OUT_OF_RES;
	}
	attribute->set_attribute_type(attribute, KEY_LENGTH);
	attribute->set_value(attribute, 12);
 	
 	
    /* 
     * Diffie-Hellman Group 
     */
 	transform = transform_substructure_create();
	if (transform == NULL)
	{
		proposal->destroy(proposal);
		return OUT_OF_RES;
	}
	status = proposal->add_transform_substructure(proposal, transform);
	if (status != SUCCESS)
	{
		proposal->destroy(proposal);
		return OUT_OF_RES;
	}
	transform->set_is_last_transform(transform, FALSE);
	transform->set_transform_type(transform, DIFFIE_HELLMAN_GROUP);
	transform->set_transform_id(transform, MODP_1024_BIT);
	
	iterator->insert_after(iterator, (void*)proposal);
	
	return SUCCESS;
}
	
static status_t select_proposals_for_host(private_configuration_manager_t *this, host_t *host, linked_list_iterator_t *in, linked_list_iterator_t *out)
{
	
	
	return FAILED;
}

static status_t is_dh_group_allowed_for_host(private_configuration_manager_t *this, host_t *host, diffie_hellman_group_t group, bool *allowed)
{
	if (group == MODP_768_BIT ||
		group == MODP_1024_BIT)
	{
		*allowed = TRUE;		
	}
	*allowed = FALSE;
	return SUCCESS;
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
	this->public.is_dh_group_allowed_for_host = (status_t(*)(configuration_manager_t*,host_t*,diffie_hellman_group_t,bool*)) is_dh_group_allowed_for_host;

	return (&this->public);
}
