/**
 * @file local_connection_store.c
 * 
 * @brief Implementation of local_connection_store_t.
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

#include "local_connection_store.h"

#include <utils/linked_list.h>
#include <utils/logger_manager.h>


typedef struct private_local_connection_store_t private_local_connection_store_t;

/**
 * Private data of an local_connection_store_t object
 */
struct private_local_connection_store_t {

	/**
	 * Public part
	 */
	local_connection_store_t public;
	
	/**
	 * stored connection
	 */
	linked_list_t *connections;
	
	/**
	 * Assigned logger
	 */
	logger_t *logger;
};


/**
 * Implementation of connection_store_t.get_connection_by_hosts.
 */
static connection_t *get_connection_by_hosts(private_local_connection_store_t *this, host_t *my_host, host_t *other_host)
{
	iterator_t *iterator;
	connection_t *current, *found = NULL;
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "getting config for hosts %s - %s", 
					  my_host->get_address(my_host), other_host->get_address(other_host));
	
	iterator = this->connections->create_iterator(this->connections, TRUE);
	while (iterator->has_next(iterator))
	{
		host_t *config_my_host, *config_other_host;
		
		iterator->current(iterator, (void**)&current);

		config_my_host = current->get_my_host(current);
		config_other_host = current->get_other_host(current);

		/* first check if ip is equal */
		if(config_other_host->ip_equals(config_other_host, other_host))
		{
			this->logger->log(this->logger, CONTROL|LEVEL2, "config entry with remote host %s", 
							  config_other_host->get_address(config_other_host));
			/* could be right one, check my_host for default route*/
			if (config_my_host->is_default_route(config_my_host))
			{
				found = current->clone(current);
				break;
			}
			/* check now if host informations are the same */
			else if (config_my_host->ip_equals(config_my_host,my_host))
			{
				found = current->clone(current);
				break;
			}
			
		}
		/* Then check for wildcard hosts!
		* TODO
		* actually its only checked if other host with default route can be found! */
		else if (config_other_host->is_default_route(config_other_host))
		{
			/* could be right one, check my_host for default route*/
			if (config_my_host->is_default_route(config_my_host))
			{
				found = current->clone(current);
				break;
			}
			/* check now if host informations are the same */
			else if (config_my_host->ip_equals(config_my_host,my_host))
			{
				found = current->clone(current);
				break;
			}
		}
	}
	iterator->destroy(iterator);
	
	/* apply hosts as they are supplied since my_host may be %defaultroute, and other_host may be %any. */
	if (found)
	{
		found->update_my_host(found, my_host->clone(my_host));
		found->update_other_host(found, other_host->clone(other_host));
	}
	
	return found;
}

/**
 * Implementation of connection_store_t.get_connection_by_ids.
 */
static connection_t *get_connection_by_ids(private_local_connection_store_t *this, identification_t *my_id, identification_t *other_id)
{
	iterator_t *iterator;
	connection_t *current, *found = NULL;
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "getting config for ids %s - %s", 
					  my_id->get_string(my_id), other_id->get_string(other_id));
	
	iterator = this->connections->create_iterator(this->connections, TRUE);
	while (iterator->has_next(iterator))
	{
		identification_t *config_my_id, *config_other_id;
		
		iterator->current(iterator, (void**)&current);
		
		config_my_id = current->get_my_id(current);
		config_other_id = current->get_other_id(current);
		
		/* first check if ids are equal 
		* TODO: Add wildcard checks */
		if (config_other_id->equals(config_other_id, other_id) &&
			config_my_id->equals(config_my_id, my_id))
		{
			this->logger->log(this->logger, CONTROL|LEVEL2, "config entry with remote id %s", 
							  config_other_id->get_string(config_other_id));
			found = current->clone(current);
			break;
		}
	}
	iterator->destroy(iterator);
	
	return found;
}

/**
 * Implementation of connection_store_t.add_connection.
 */
status_t add_connection(private_local_connection_store_t *this, connection_t *connection)
{
	this->connections->insert_last(this->connections, connection);
	return SUCCESS;
}

/**
 * Implementation of connection_store_t.destroy.
 */
static void destroy (private_local_connection_store_t *this)
{
	connection_t *connection;
	
	while (this->connections->remove_last(this->connections, (void**)&connection) == SUCCESS)
	{
		connection->destroy(connection);
	}
	this->connections->destroy(this->connections);
	free(this);
}

/**
 * Described in header.
 */
local_connection_store_t * local_connection_store_create()
{
	private_local_connection_store_t *this = malloc_thing(private_local_connection_store_t);

	this->public.connection_store.get_connection_by_hosts = (connection_t*(*)(connection_store_t*,host_t*,host_t*))get_connection_by_hosts;
	this->public.connection_store.get_connection_by_ids = (connection_t*(*)(connection_store_t*,identification_t*,identification_t*))get_connection_by_ids;
	this->public.connection_store.add_connection = (status_t(*)(connection_store_t*,connection_t*))add_connection;
	this->public.connection_store.destroy = (void(*)(connection_store_t*))destroy;
	
	/* private variables */
	this->connections = linked_list_create();
	this->logger = logger_manager->get_logger(logger_manager, CONFIG);

	return (&this->public);
}
