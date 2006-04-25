/**
 * @file local_policy_store.c
 * 
 * @brief Implementation of local_policy_store_t.
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

#include "local_policy_store.h"

#include <utils/linked_list.h>
#include <utils/logger_manager.h>


typedef struct private_local_policy_store_t private_local_policy_store_t;

/**
 * Private data of an local_policy_store_t object
 */
struct private_local_policy_store_t {

	/**
	 * Public part
	 */
	local_policy_store_t public;
	
	/**
	 * list of policy_t's
	 */
	linked_list_t *policies;
	
	/**
	 * Assigned logger
	 */
	logger_t *logger;
};

/**
 * Implementation of policy_store_t.add_policy.
 */
static void add_policy(private_local_policy_store_t *this, policy_t *policy)
{
	this->policies->insert_last(this->policies, (void*)policy);
}


/**
 * Implementation of policy_store_t.get_policy.
 */
static policy_t *get_policy(private_local_policy_store_t *this, identification_t *my_id, identification_t *other_id)
{
	iterator_t *iterator;
	policy_t *current, *found = NULL;
	
	iterator = this->policies->create_iterator(this->policies, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void **)&current);
		identification_t *config_my_id = current->get_my_id(current);
		identification_t *config_other_id = current->get_other_id(current);
		
		/* check other host first */
		if (config_other_id->belongs_to(config_other_id, other_id))
		{
			/* get it if my_id not specified */
			if (my_id == NULL)
			{
				found = current->clone(current);
				break;
			}
			if (config_my_id->belongs_to(config_my_id, my_id))
			{
				found = current->clone(current);
				break;
			}
		}
	}
	iterator->destroy(iterator);
	
	/* apply IDs as they are requsted, since they may be configured as %any or such */
	if (found)
	{
		if (my_id)
		{
			found->update_my_id(found, my_id->clone(my_id));
		}
		found->update_other_id(found, other_id->clone(other_id));
	}
	return found;
}

/**
 * Implementation of policy_store_t.destroy.
 */
static void destroy(private_local_policy_store_t *this)
{
	policy_t *policy;
	
	while (this->policies->remove_last(this->policies, (void**)&policy) == SUCCESS)
	{
		policy->destroy(policy);
	}
	this->policies->destroy(this->policies);
	free(this);
}

/**
 * Described in header.
 */
local_policy_store_t *local_policy_store_create()
{
	private_local_policy_store_t *this = malloc_thing(private_local_policy_store_t);
	
	this->public.policy_store.add_policy = (void(*)(policy_store_t*,policy_t*))add_policy;
	this->public.policy_store.get_policy = (policy_t*(*)(policy_store_t*,identification_t*,identification_t*))get_policy;
	this->public.policy_store.destroy = (void(*)(policy_store_t*))destroy;
	
	/* private variables */
	this->policies = linked_list_create();
	this->logger = logger_manager->get_logger(logger_manager, CONFIG);
	
	return (&this->public);
}
