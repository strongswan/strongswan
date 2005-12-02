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
#include <daemon.h>
#include <utils/allocator.h>

typedef struct configuration_entry_t configuration_entry_t;

/* A configuration entry combines a configuration name with a init and sa 
 * configuration represented as init_config_t and sa_config_t objects.
 */
struct configuration_entry_t {
	
	/**
	 * Configuration name.
	 * 
	 */
	char *name;
	
	/**
	 * Configuration for IKE_SA_INIT exchange.
	 */
	init_config_t *init_config;

	/**
	 * Configuration for all phases after IKE_SA_INIT exchange.
	 */
	sa_config_t *sa_config;
	
	/**
	 * Destroys a configuration_entry_t
	 * 
	 * 
	 * @param this				calling object
	 */
	void (*destroy) (configuration_entry_t *this);
};

static void configuration_entry_destroy (configuration_entry_t *this)
{
	allocator_free(this->name);
	allocator_free(this);
}

/**
 * Creates a configuration_entry_t object 
 * 
 * @param name 			name of the configuration entry (gets copied)
 * @param init_config	object of type init_config_t
 * @param sa_config		object of type sa_config_t
 */
configuration_entry_t * configuration_entry_create(char * name, init_config_t * init_config, sa_config_t * sa_config)
{
	configuration_entry_t *entry = allocator_alloc_thing(configuration_entry_t);

	/* functions */
	entry->destroy = configuration_entry_destroy;

	/* private data */
	entry->init_config = init_config;
	entry->sa_config = sa_config;
	entry->name = allocator_alloc(strlen(name) + 1);
	strcpy(entry->name,name);
	return entry;
}


typedef struct private_configuration_manager_t private_configuration_manager_t;

/**
 * Private data of an configuration_t object
 */
struct private_configuration_manager_t {

	/**
	 * Public part of configuration manager.
	 */
	configuration_manager_t public;

	/**
	 * Holding all configurations.
	 */
	linked_list_t *configurations;

	/**
	 * Holding all init_configs.
	 */
	linked_list_t *init_configs;

	/**
	 * Holding all init_configs.
	 */
	linked_list_t *sa_configs;


	/**
	 * Assigned logger object.
	 */
	logger_t *logger;
	

	/**
	 * Max number of retransmitted requests.
	 */	
	u_int32_t max_retransmit_count;
	
	/**
	 * First retransmit timeout in ms.
	 */
	u_int32_t first_retransmit_timeout;

	/**
	 * Load default configuration
	 * 
	 * 
	 * @param this				calling object
	 * @param name				name for the configuration
	 * @param init_config		init_config_t object
	 * @param sa_config			sa_config_t object
	 */
	void (*add_new_configuration) (private_configuration_manager_t *this, char *name, init_config_t *init_config, sa_config_t *sa_config);
	
	/**
	 * Load default configuration
	 * 
	 * 
	 * @param this				calling object
	 */
	void (*load_default_config) (private_configuration_manager_t *this);
};

/**
 * Implementation of private_configuration_manager_t.load_default_config.
 */
static void load_default_config (private_configuration_manager_t *this)
{
	init_config_t *init_config1, *init_config2, *init_config3;
	ike_proposal_t proposals[2];
	child_proposal_t child_proposals[1];
	sa_config_t *sa_config1, *sa_config2, *sa_config3;
	traffic_selector_t *ts;
	
	init_config1 = init_config_create("152.96.193.131","152.96.193.131",IKEV2_UDP_PORT,IKEV2_UDP_PORT);
	init_config2 = init_config_create("152.96.193.131","152.96.193.130",IKEV2_UDP_PORT,IKEV2_UDP_PORT);
	init_config3 = init_config_create("0.0.0.0","127.0.0.1",IKEV2_UDP_PORT,IKEV2_UDP_PORT);
	ts = traffic_selector_create_from_string(1, TS_IPV4_ADDR_RANGE, "0.0.0.0", 0, "255.255.255.255", 65535);
	

	proposals[0].encryption_algorithm = ENCR_AES_CBC;
	proposals[0].encryption_algorithm_key_length = 16;
	proposals[0].integrity_algorithm = AUTH_HMAC_MD5_96;
	proposals[0].integrity_algorithm_key_length = 16;
	proposals[0].pseudo_random_function = PRF_HMAC_MD5;
	proposals[0].pseudo_random_function_key_length = 16;
	proposals[0].diffie_hellman_group = MODP_1024_BIT;
	
	proposals[1] = proposals[0];
	proposals[1].integrity_algorithm = AUTH_HMAC_SHA1_96;
	proposals[1].integrity_algorithm_key_length = 20;
	proposals[1].pseudo_random_function = PRF_HMAC_SHA1;
	proposals[1].pseudo_random_function_key_length = 20;

	init_config1->add_proposal(init_config1,1,proposals[0]);
	init_config1->add_proposal(init_config1,1,proposals[1]);
	init_config2->add_proposal(init_config2,1,proposals[0]);
	init_config2->add_proposal(init_config2,1,proposals[1]);
	init_config3->add_proposal(init_config3,1,proposals[0]);
	init_config3->add_proposal(init_config3,1,proposals[1]);
	
	sa_config1 = sa_config_create(ID_IPV4_ADDR, "152.96.193.131", 
								  ID_IPV4_ADDR, "152.96.193.130",
								  SHARED_KEY_MESSAGE_INTEGRITY_CODE);
								  
	sa_config1->add_traffic_selector_initiator(sa_config1,ts);
	sa_config1->add_traffic_selector_responder(sa_config1,ts);

	sa_config2 = sa_config_create(ID_IPV4_ADDR, "152.96.193.130", 
								  ID_IPV4_ADDR, "152.96.193.131",
								  SHARED_KEY_MESSAGE_INTEGRITY_CODE);

	sa_config2->add_traffic_selector_initiator(sa_config2,ts);
	sa_config2->add_traffic_selector_responder(sa_config2,ts);

	sa_config3 = sa_config_create(ID_IPV4_ADDR, "127.0.0.1", 
								  ID_IPV4_ADDR, "127.0.0.1",
								  SHARED_KEY_MESSAGE_INTEGRITY_CODE);

	sa_config3->add_traffic_selector_initiator(sa_config3,ts);
	sa_config3->add_traffic_selector_responder(sa_config3,ts);
	
	ts->destroy(ts);
	
	/* ah and esp prop */
	child_proposals[0].ah.is_set = TRUE;
	child_proposals[0].ah.integrity_algorithm = AUTH_HMAC_MD5_96;
	child_proposals[0].ah.integrity_algorithm_key_size = 16;
	child_proposals[0].ah.diffie_hellman_group = MODP_1024_BIT;
	child_proposals[0].ah.extended_sequence_numbers = NO_EXT_SEQ_NUMBERS;

	child_proposals[0].esp.is_set = TRUE;
	child_proposals[0].esp.diffie_hellman_group = MODP_1024_BIT;
	child_proposals[0].esp.encryption_algorithm = ENCR_AES_CBC;
	child_proposals[0].esp.encryption_algorithm_key_size = 16;
	child_proposals[0].esp.integrity_algorithm = AUTH_UNDEFINED;
	child_proposals[0].esp.extended_sequence_numbers = NO_EXT_SEQ_NUMBERS;
	child_proposals[0].esp.spi[0] = 2;
	child_proposals[0].esp.spi[1] = 2;
	child_proposals[0].esp.spi[2] = 2;
	child_proposals[0].esp.spi[3] = 2;
	
	sa_config1->add_proposal(sa_config1, &child_proposals[0]);
	sa_config2->add_proposal(sa_config2, &child_proposals[0]);
	sa_config3->add_proposal(sa_config3, &child_proposals[0]);

	this->add_new_configuration(this,"pinflb31",init_config1,sa_config2);
	this->add_new_configuration(this,"pinflb30",init_config2,sa_config1);
	this->add_new_configuration(this,"localhost",init_config3,sa_config3);

}

/**
 * Implementation of configuration_manager_t.get_init_config_for_host.
 */
static status_t get_init_config_for_host (private_configuration_manager_t *this, host_t *my_host, host_t *other_host,init_config_t **init_config)
{
	iterator_t *iterator;
	status_t status = NOT_FOUND;
	
	iterator = this->configurations->create_iterator(this->configurations,TRUE);
	
	while (iterator->has_next(iterator))
	{
		configuration_entry_t *entry;
		host_t *config_my_host;
		host_t *config_other_host;
		
		iterator->current(iterator,(void **) &entry);

		config_my_host = entry->init_config->get_my_host(entry->init_config);
		config_other_host = entry->init_config->get_other_host(entry->init_config);

		/* first check if ip is equal */
		if(config_other_host->ip_is_equal(config_other_host,other_host))
		{
			/* could be right one, check my_host for default route*/
			if (config_my_host->is_default_route(config_my_host))
			{
				*init_config = entry->init_config;
				status = SUCCESS;
				break;
			}
			/* check now if host informations are the same */
			else if (config_my_host->ip_is_equal(config_my_host,my_host))
			{
				*init_config = entry->init_config;
				status = SUCCESS;
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
				*init_config = entry->init_config;
				status = SUCCESS;
				break;
			}
			/* check now if host informations are the same */
			else if (config_my_host->ip_is_equal(config_my_host,my_host))
			{
				*init_config = entry->init_config;
				status = SUCCESS;
				break;
			}
		}
	}
	
	iterator->destroy(iterator);
	
	return status;
}

/**
 * Implementation of configuration_manager_t.get_init_config_for_name.
 */
static status_t get_init_config_for_name (private_configuration_manager_t *this, char *name, init_config_t **init_config)
{
	iterator_t *iterator;
	status_t status = NOT_FOUND;
	
	iterator = this->configurations->create_iterator(this->configurations,TRUE);
	
	while (iterator->has_next(iterator))
	{
		configuration_entry_t *entry;
		iterator->current(iterator,(void **) &entry);

		if (strcmp(entry->name,name) == 0)
		{

			/* found configuration */
			*init_config = entry->init_config;
			status = SUCCESS;
			break;
		}
	}
	
	iterator->destroy(iterator);
	
	return status;
}
	
/**
 * Implementation of configuration_manager_t.get_sa_config_for_name.
 */
static status_t get_sa_config_for_name (private_configuration_manager_t *this, char *name, sa_config_t **sa_config)
{
	iterator_t *iterator;
	status_t status = NOT_FOUND;
	
	iterator = this->configurations->create_iterator(this->configurations,TRUE);
	
	while (iterator->has_next(iterator))
	{
		configuration_entry_t *entry;
		iterator->current(iterator,(void **) &entry);

		if (strcmp(entry->name,name) == 0)
		{
			/* found configuration */
			*sa_config = entry->sa_config;
			status = SUCCESS;
			break;
		}
	}
	
	iterator->destroy(iterator);
	
	return status;
}

/**
 * Implementation of configuration_manager_t.get_sa_config_for_init_config_and_id.
 */
static status_t get_sa_config_for_init_config_and_id (private_configuration_manager_t *this, init_config_t *init_config, identification_t *other_id, identification_t *my_id,sa_config_t **sa_config)
{	
	iterator_t *iterator;
	status_t status = NOT_FOUND;
	
	iterator = this->configurations->create_iterator(this->configurations,TRUE);
	
	while (iterator->has_next(iterator))
	{
		configuration_entry_t *entry;
		iterator->current(iterator,(void **) &entry);

		if (entry->init_config == init_config)
		{
			identification_t *config_my_id = entry->sa_config->get_my_id(entry->sa_config);
			identification_t *config_other_id = entry->sa_config->get_other_id(entry->sa_config);

			/* host informations seem to be the same */
			if (config_other_id->equals(config_other_id,other_id))
			{
				/* other ids seems to match */
				
				if (my_id == NULL)
				{
					/* first matching one is selected */
					
					/* TODO priorize found entries */
					*sa_config = entry->sa_config;
					status = SUCCESS;
					break;
				}

				if (config_my_id->equals(config_my_id,my_id))
				{
					*sa_config = entry->sa_config;
					status = SUCCESS;
					break;
				}

			}
		}
	}
	
	iterator->destroy(iterator);
	
	return status;
}

/**
 * Implementation of private_configuration_manager_t.add_new_configuration.
 */
static void add_new_configuration (private_configuration_manager_t *this, char *name, init_config_t *init_config, sa_config_t *sa_config)
{
	iterator_t *iterator;
	bool found;
	
	iterator = this->init_configs->create_iterator(this->init_configs,TRUE);
	found = FALSE;
	while (iterator->has_next(iterator))
	{
		init_config_t *found_init_config;
		iterator->current(iterator,(void **) &found_init_config);
		if (init_config == found_init_config)
		{
			found = TRUE;
			break;
		}
	}
	iterator->destroy(iterator);
	if (!found)
	{
		this->init_configs->insert_first(this->init_configs,init_config);
	}
	
	iterator = this->sa_configs->create_iterator(this->sa_configs,TRUE);
	found = FALSE;
	while (iterator->has_next(iterator))
	{
		sa_config_t *found_sa_config;
		iterator->current(iterator,(void **) &found_sa_config);
		if (sa_config == found_sa_config)
		{
			found = TRUE;
			break;
		}
	}
	iterator->destroy(iterator);
	if (!found)
	{
		this->sa_configs->insert_first(this->sa_configs,sa_config);
	}

	this->configurations->insert_first(this->configurations,configuration_entry_create(name,init_config,sa_config));
}

static status_t get_retransmit_timeout (private_configuration_manager_t *this, u_int32_t retransmit_count, u_int32_t *timeout)
{
	if ((retransmit_count > this->max_retransmit_count) && (this->max_retransmit_count != 0))
	{
		return FAILED;
	}
	
	/**
	 * TODO implement a good retransmit policy
	 */
	*timeout = this->first_retransmit_timeout * (retransmit_count + 1);
	
	return SUCCESS;
}

/**
 * Implementation of configuration_manager_t.destroy.
 */
static void destroy(private_configuration_manager_t *this)
{
	this->logger->log(this->logger,CONTROL | MORE, "Going to destroy configuration manager ");

	while (this->configurations->get_count(this->configurations) > 0)
	{
		configuration_entry_t *entry;
		this->configurations->remove_first(this->configurations,(void **) &entry);
		entry->destroy(entry);
	}
	/* todo delete all config objects */
	
	this->configurations->destroy(this->configurations);
	
	while (this->sa_configs->get_count(this->sa_configs) > 0)
	{
		sa_config_t *sa_config;
		this->sa_configs->remove_first(this->sa_configs,(void **) &sa_config);
		sa_config->destroy(sa_config);
	}

	this->sa_configs->destroy(this->sa_configs);
	
	while (this->init_configs->get_count(this->init_configs) > 0)
	{
		init_config_t *init_config;
		this->init_configs->remove_first(this->init_configs,(void **) &init_config);
		init_config->destroy(init_config);
	}
	this->init_configs->destroy(this->init_configs);
	
	this->logger->log(this->logger,CONTROL | MOST, "Destroy assigned logger");
	charon->logger_manager->destroy_logger(charon->logger_manager,this->logger);
	allocator_free(this);
}

/*
 * Described in header-file
 */
configuration_manager_t *configuration_manager_create(u_int32_t first_retransmit_timeout,u_int32_t max_retransmit_count)
{
	private_configuration_manager_t *this = allocator_alloc_thing(private_configuration_manager_t);

	/* public functions */
	this->public.destroy = (void(*)(configuration_manager_t*))destroy;
	this->public.get_init_config_for_name = (status_t (*) (configuration_manager_t *, char *, init_config_t **)) get_init_config_for_name;
	this->public.get_init_config_for_host = (status_t (*) (configuration_manager_t *, host_t *, host_t *,init_config_t **)) get_init_config_for_host;
	this->public.get_sa_config_for_name =(status_t (*) (configuration_manager_t *, char *, sa_config_t **)) get_sa_config_for_name;
	this->public.get_sa_config_for_init_config_and_id =(status_t (*) (configuration_manager_t *, init_config_t *, identification_t *, identification_t *,sa_config_t **)) get_sa_config_for_init_config_and_id;
	this->public.get_retransmit_timeout = (status_t (*) (configuration_manager_t *, u_int32_t retransmit_count, u_int32_t *timeout))get_retransmit_timeout;
	
	/* private functions */
	this->load_default_config = load_default_config;
	this->add_new_configuration = add_new_configuration;
	
	/* private variables */
	this->logger = charon->logger_manager->create_logger(charon->logger_manager,CONFIGURATION_MANAGER,NULL);
	this->configurations = linked_list_create();
	this->sa_configs = linked_list_create();
	this->init_configs = linked_list_create();
	this->max_retransmit_count = max_retransmit_count;
	this->first_retransmit_timeout = first_retransmit_timeout;
	
	this->load_default_config(this);

	return (&this->public);
}
