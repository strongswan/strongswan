/**
 * @file configuration.c
 * 
 * @brief Configuration class used to store IKE_SA-configurations.
 * 
 * Object of this type represents the configuration for all IKE_SA's and their child_sa's.
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

#include <types.h>
#include <globals.h>
#include <utils/allocator.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/proposal_substructure.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/transform_attribute.h>

typedef struct private_configuration_manager_t private_configuration_manager_t;

/**
 * Private data of an configuration_t object
 */
struct private_configuration_manager_t {

	/**
	 * Public part
	 */
	configuration_manager_t public;

	/**
	 * Assigned logger object 
	 */
	logger_t *logger;
};

/**
 * Implements function configuration_manager_t.get_remote_host.
 */
static status_t get_remote_host(private_configuration_manager_t *this, char *name, host_t **host)
{
	/*
	 * For testing purposes, hard coded host informations for two configurations are returned.
	 * 
	 * Further improvements could store them in a linked list or hash table.
	 */

	host_t *remote;
	status_t status = SUCCESS;
	
	if (strcmp(name, "pinflb30") == 0)
	{
		remote = host_create(AF_INET, "152.96.193.130", 500);
	}
	else if (strcmp(name, "pinflb31") == 0)
	{
		remote = host_create(AF_INET, "152.96.193.131", 500);
	}
	else if (strcmp(name, "localhost") == 0)
	{
		remote = host_create(AF_INET, "127.0.0.1", 4500);
	}
	else
	{
		status = NOT_FOUND;
	}

	*host = remote;
	return status;
}

/**
 * Implements function configuration_manager_t.get_local_host.
 */
static status_t get_local_host(private_configuration_manager_t *this, char *name, host_t **host)
{
	/*
	 * For testing purposes, only the default route is returned for each configuration.
	 * 
	 * Further improvements could store different local host informations in a linked list or hash table.
	 */
	*host = host_create(AF_INET, "0.0.0.0", 0);
	return SUCCESS;
}

/**
 * Implements function configuration_manager_t.get_dh_group_number.
 */
static status_t get_dh_group_number(private_configuration_manager_t *this,char *name, u_int16_t *dh_group_number, u_int16_t priority)
{
	/* Currently only two dh_group_numbers are supported for each configuration*/
	
	if (priority == 1)
	{
		*dh_group_number = MODP_1024_BIT;
	}
	else
	{
		*dh_group_number = MODP_768_BIT;
	}
	return SUCCESS;
}

/**
 * Implements function configuration_manager_t.get_proposals_for_host.
 */
static status_t get_proposals_for_host(private_configuration_manager_t *this, host_t *host, iterator_t *iterator)
{
	/* 
	 * Currently the following hard coded proposal is created and returned for all hosts:
	 * - ENCR_AES_CBC 128Bit
	 * - PRF_HMAC_MD5 128Bit
	 * - AUTH_HMAC_MD5_96 128Bit
	 * - MODP_1024_BIT
	 */
	proposal_substructure_t *proposal;
	transform_substructure_t *transform;
	transform_attribute_t *attribute;
	
	proposal = proposal_substructure_create();
	
	proposal->set_proposal_number(proposal, 1);
	proposal->set_protocol_id(proposal, 1);
	
	/* 
	 * Encryption Algorithm 
	 */
	transform = transform_substructure_create();

	proposal->add_transform_substructure(proposal, transform);

	transform->set_transform_type(transform, ENCRYPTION_ALGORITHM);
	transform->set_transform_id(transform, ENCR_AES_CBC);
	
	attribute = transform_attribute_create();

	transform->add_transform_attribute(transform, attribute);

	attribute->set_attribute_type(attribute, KEY_LENGTH);
	attribute->set_value(attribute, 16);
	
 	/* 
 	 * Pseudo-random Function
 	 */
 	transform = transform_substructure_create();

	proposal->add_transform_substructure(proposal, transform);

	transform->set_transform_type(transform, PSEUDO_RANDOM_FUNCTION);
	transform->set_transform_id(transform, PRF_HMAC_MD5);
	
	attribute = transform_attribute_create();

	transform->add_transform_attribute(transform, attribute);

	attribute->set_attribute_type(attribute, KEY_LENGTH);
	attribute->set_value(attribute, 16);

 	
 	/* 
 	 * Integrity Algorithm 
 	 */
 	transform = transform_substructure_create();

	proposal->add_transform_substructure(proposal, transform);

	transform->set_transform_type(transform, INTEGRITY_ALGORITHM);
	transform->set_transform_id(transform, AUTH_HMAC_MD5_96);
	
	attribute = transform_attribute_create();

	transform->add_transform_attribute(transform, attribute);

	attribute->set_attribute_type(attribute, KEY_LENGTH);
	attribute->set_value(attribute, 16);
 	
 	
    /* 
     * Diffie-Hellman Group 
     */
 	transform = transform_substructure_create();

	proposal->add_transform_substructure(proposal, transform);

	transform->set_transform_type(transform, DIFFIE_HELLMAN_GROUP);
	transform->set_transform_id(transform, MODP_1024_BIT);
	
	iterator->insert_after(iterator, (void*)proposal);
	
	return SUCCESS;
}
	
/**
 * Implements function configuration_manager_t.select_proposals_for_host.
 */
static status_t select_proposals_for_host(private_configuration_manager_t *this, host_t *host, iterator_t *in, iterator_t *out)
{
	/* Currently the first suggested proposal is selected, cloned and then returned*/
	proposal_substructure_t *first_suggested_proposal;
	proposal_substructure_t *selected_proposal;
	
	this->logger->log(this->logger,CONTROL | MORE, "Going to select first suggested proposal");
	if (!in->has_next(in))
	{
		this->logger->log(this->logger,ERROR | MORE, "No proposal suggested");
		/* no suggested proposal! */
		return FAILED;
	}
	
	in->current(in,(void **) &first_suggested_proposal);

	first_suggested_proposal->clone(first_suggested_proposal,&selected_proposal);
	
	out->insert_after(out,selected_proposal);
	return SUCCESS;
}

/**
 * Implements function configuration_manager_t.check_selected_proposals_for_host.
 */
static status_t check_selected_proposals_for_host (private_configuration_manager_t *this, host_t *host, iterator_t *proposals,bool *valid)
{
	/*
	 * Currently the given proposals are not checked if they are valid for specific host!
	 * 
	 * The first proposal is taken
	 */

	this->logger->log(this->logger,CONTROL|MORE, "Going to check selected proposals");
	return SUCCESS;
}

/**
 * Implements function configuration_manager_t.is_dh_group_allowed_for_host.
 */
static status_t is_dh_group_allowed_for_host(private_configuration_manager_t *this, host_t *host, diffie_hellman_group_t group, bool *allowed)
{
	/*
	 * Only the two DH groups 768 and 1024 are supported for each configuration
	 */
	
	if (group == MODP_768_BIT || group == MODP_1024_BIT)
	{
		*allowed = TRUE;		
	}
	*allowed = FALSE;
	
	this->logger->log(this->logger,CONTROL | MORE, "DH group %s is %s",mapping_find(diffie_hellman_group_m, group),(allowed)? "allowed" : "not allowed");
	return SUCCESS;
}


/**
 * Implements function destroy of configuration_t.
 * See #configuration_s.destroy for description.
 */
static status_t destroy(private_configuration_manager_t *this)
{
	this->logger->log(this->logger,CONTROL | MORE, "Going to destroy configuration manager ");
	
	this->logger->log(this->logger,CONTROL | MOST, "Destroy assigned logger");
	global_logger_manager->destroy_logger(global_logger_manager,this->logger);
	allocator_free(this);
	return SUCCESS;
}

/*
 * Described in header-file
 */
configuration_manager_t *configuration_manager_create()
{
	private_configuration_manager_t *this = allocator_alloc_thing(private_configuration_manager_t);

	/* public functions */
	this->public.destroy = (status_t(*)(configuration_manager_t*))destroy;
	this->public.get_remote_host = (status_t(*)(configuration_manager_t*,char*,host_t**))get_remote_host;
	this->public.get_local_host = (status_t(*)(configuration_manager_t*,char*,host_t**))get_local_host;
	this->public.get_dh_group_number = (status_t(*)(configuration_manager_t*,char*,u_int16_t *, u_int16_t))get_dh_group_number;
	this->public.get_proposals_for_host = (status_t(*)(configuration_manager_t*,host_t*,iterator_t*))get_proposals_for_host;
	this->public.select_proposals_for_host = (status_t(*)(configuration_manager_t*,host_t*,iterator_t*,iterator_t*))select_proposals_for_host;
	this->public.check_selected_proposals_for_host =  (status_t (*) (configuration_manager_t *, host_t *, iterator_t *,bool *)) check_selected_proposals_for_host;
	this->public.is_dh_group_allowed_for_host = (status_t(*)(configuration_manager_t*,host_t*,diffie_hellman_group_t,bool*)) is_dh_group_allowed_for_host;

	/* private variables */
	this->logger = global_logger_manager->create_logger(global_logger_manager,CONFIGURATION_MANAGER,NULL);

	return (&this->public);
}
