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

#include <string.h>

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
	typedef enum {
		PRIO_UNDEFINED=		0x00,
		PRIO_ADDR_ANY= 		0x01,
		PRIO_ADDR_MATCH=	0x02
	} prio_t;

	prio_t best_prio = PRIO_UNDEFINED;

	iterator_t *iterator;
	connection_t *candidate;
	connection_t *found = NULL;
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "searching connection for host pair %s...%s",
					  my_host->get_address(my_host), other_host->get_address(other_host));

	iterator = this->connections->create_iterator(this->connections, TRUE);

	/* determine closest matching connection */
	while (iterator->has_next(iterator))
	{
		host_t *candidate_my_host;
		host_t *candidate_other_host;
		
		iterator->current(iterator, (void**)&candidate);

		candidate_my_host    = candidate->get_my_host(candidate);
		candidate_other_host = candidate->get_other_host(candidate);

		/* my_host addresses must match*/
		if (my_host->ip_equals(my_host, candidate_my_host))
		{
			prio_t prio = PRIO_UNDEFINED;

			/* exact match of peer host address or wildcard address? */
			if (other_host->ip_equals(other_host, candidate_other_host))
			{
				prio |= PRIO_ADDR_MATCH;
			}
			else if (candidate_other_host->is_anyaddr(candidate_other_host))
			{
				prio |= PRIO_ADDR_ANY;
			}

			this->logger->log(this->logger, CONTROL|LEVEL2,
							 "candidate connection \"%s\": %s...%s (prio=%d)",
							  candidate->get_name(candidate),
							  candidate_my_host->get_address(candidate_my_host),
							  candidate_other_host->get_address(candidate_other_host),
							  prio);

			if (prio > best_prio)
			{
				found = candidate;
				best_prio = prio;
			}			
		}
	}
	iterator->destroy(iterator);
	
	if (found)
	{
		host_t *found_my_host    = found->get_my_host(found);
		host_t *found_other_host = found->get_other_host(found);
		
		this->logger->log(this->logger, CONTROL|LEVEL1,
						 "found matching connection \"%s\": %s...%s (prio=%d)",
						  found->get_name(found),
						  found_my_host->get_address(found_my_host),
						  found_other_host->get_address(found_other_host),
						  best_prio);

		found = found->clone(found);
		if (best_prio & PRIO_ADDR_ANY)
		{
			/* replace %any by the peer's address */
			found->update_other_host(found, other_host->clone(other_host));
		}
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
 * Implementation of connection_store_t.get_connection_by_name.
 */
static connection_t *get_connection_by_name(private_local_connection_store_t *this, char *name)
{
	iterator_t *iterator;
	connection_t *current, *found = NULL;
	
	iterator = this->connections->create_iterator(this->connections, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current);
		if (strcmp(name, current->get_name(current)) == 0)
		{
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
static status_t add_connection(private_local_connection_store_t *this, connection_t *connection)
{
	this->connections->insert_last(this->connections, connection);
	return SUCCESS;
}

/**
 * Implementation of connection_store_t.log_connections.
 */
void log_connections(private_local_connection_store_t *this, logger_t *logger, char *name)
{
	iterator_t *iterator;
	connection_t *current, *found = NULL;
	
	if (logger == NULL)
	{
		logger = this->logger;
	}
	
	logger->log(logger, CONTROL, "templates:");
	
	iterator = this->connections->create_iterator(this->connections, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current);
		if (!name || strcmp(name, current->get_name(current)) == 0)
		{
			identification_t *my_id, *other_id;
			host_t *my_host, *other_host;
			my_id = current->get_my_id(current);
			other_id = current->get_other_id(current);
			my_host = current->get_my_host(current);
			other_host = current->get_other_host(current);
			logger->log(logger, CONTROL, "  \"%s\": %s[%s]...%s[%s]",
						current->get_name(current),
						my_host->get_address(my_host), my_id->get_string(my_id),
						other_host->get_address(other_host), other_id->get_string(other_id));
		}
	}
	iterator->destroy(iterator);
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
local_connection_store_t * local_connection_store_create(void)
{
	private_local_connection_store_t *this = malloc_thing(private_local_connection_store_t);

	this->public.connection_store.get_connection_by_hosts = (connection_t*(*)(connection_store_t*,host_t*,host_t*))get_connection_by_hosts;
	this->public.connection_store.get_connection_by_ids = (connection_t*(*)(connection_store_t*,identification_t*,identification_t*))get_connection_by_ids;
	this->public.connection_store.get_connection_by_name = (connection_t*(*)(connection_store_t*,char*))get_connection_by_name;
	this->public.connection_store.add_connection = (status_t(*)(connection_store_t*,connection_t*))add_connection;
	this->public.connection_store.log_connections = (void(*)(connection_store_t*,logger_t*,char*))log_connections;
	this->public.connection_store.destroy = (void(*)(connection_store_t*))destroy;
	
	/* private variables */
	this->connections = linked_list_create();
	this->logger = logger_manager->get_logger(logger_manager, CONFIG);

	return (&this->public);
}
