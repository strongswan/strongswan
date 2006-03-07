/**
 * @file starter_configuration.c
 * 
 * @brief Implementation of starter_configuration_t.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include "starter_configuration.h"

#include <types.h>
#include <daemon.h>
#include <utils/allocator.h>


/**
 * First retransmit timeout in milliseconds.
 * 
 * Timeout value is increasing in each retransmit round.
 */
#define RETRANSMIT_TIMEOUT 3000

/**
 * Timeout in milliseconds after that a half open IKE_SA gets deleted.
 */
#define HALF_OPEN_IKE_SA_TIMEOUT 30000

/**
 * Max retransmit count.
 * 0 for infinite. The max time a half open IKE_SA is alive is set by 
 * RETRANSMIT_TIMEOUT.
 */
#define MAX_RETRANSMIT_COUNT 0


struct sockaddr_un socket_addr = { AF_UNIX, "/var/run/pluto.ctl"};


typedef struct preshared_secret_entry_t preshared_secret_entry_t;

/**
 * A preshared secret entry combines an identifier and a 
 * preshared secret.
 */
struct preshared_secret_entry_t {

	/**
	 * Identification.
	 */
	identification_t *identification;
	
	/**
	 * Preshared secret as chunk_t. The NULL termination is not included.
	 */	
	chunk_t preshared_secret;
};


typedef struct rsa_private_key_entry_t rsa_private_key_entry_t;

/**
 * Entry for a rsa private key.
 */
struct rsa_private_key_entry_t {

	/**
	 * Identification.
	 */
	identification_t *identification;
	
	/**
	 * Private key.
	 */	
	rsa_private_key_t* private_key;
};

typedef struct rsa_public_key_entry_t rsa_public_key_entry_t;

/**
 * Entry for a rsa private key.
 */
struct rsa_public_key_entry_t {

	/**
	 * Identification.
	 */
	identification_t *identification;
	
	/**
	 * Private key.
	 */	
	rsa_public_key_t* public_key;
};

typedef struct configuration_entry_t configuration_entry_t;

/**
 * A configuration entry combines a configuration name with a init and sa 
 * configuration represented as init_config_t and sa_config_t objects.
 * 
 * @b Constructors:
 *  - configuration_entry_create()
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
	 * @param this				calling object
	 */
	void (*destroy) (configuration_entry_t *this);
};

/**
 * Implementation of configuration_entry_t.destroy.
 */
static void configuration_entry_destroy (configuration_entry_t *this)
{
	allocator_free(this->name);
	allocator_free(this);
}

/**
 * @brief Creates a configuration_entry_t object.
 * 
 * @param name 			name of the configuration entry (gets copied)
 * @param init_config	object of type init_config_t
 * @param sa_config		object of type sa_config_t
 */
static configuration_entry_t * configuration_entry_create(char * name, init_config_t * init_config, sa_config_t * sa_config)
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

typedef struct private_starter_configuration_t private_starter_configuration_t;

/**
 * Private data of an starter_configuration_t object.
 */
struct private_starter_configuration_t {

	/**
	 * Public part of starter_configuration_t object.
	 */
	starter_configuration_t public;

	/**
	 * Holding all configurations.
	 */
	linked_list_t *configurations;

	/**
	 * Holding all managed init_configs.
	 */
	linked_list_t *init_configs;

	/**
	 * Holding all managed init_configs.
	 */
	linked_list_t *sa_configs;
	
	/**
	 * Holding all managed preshared secrets.
	 */
	linked_list_t *preshared_secrets;
	
	/**
	 * Holding all managed private secrets.
	 */
	linked_list_t *rsa_private_keys;
	
	/**
	 * Holding all managed public secrets.
	 */
	linked_list_t *rsa_public_keys;

	/**
	 * Assigned logger_t object.
	 */
	logger_t *logger;
	
	/**
	 * Max number of requests to be retransmitted.
	 * 0 for infinite.
	 */	
	u_int32_t max_retransmit_count;
	
	/**
	 * First retransmit timeout in ms.
	 */
	u_int32_t first_retransmit_timeout;
	
	/**
	 * Timeout in ms after that time a IKE_SA gets deleted.
	 */
	u_int32_t half_open_ike_sa_timeout;
	
	int socket;
	
	pthread_t assigned_thread;

	/**
	 * Adds a new IKE_SA configuration.
	 * 
	 * @param this				calling object
	 * @param name				name for the configuration
	 * @param init_config		init_config_t object
	 * @param sa_config			sa_config_t object
	 */
	void (*add_new_configuration) (private_starter_configuration_t *this, char *name, init_config_t *init_config, sa_config_t *sa_config);
	
	/**
	 * Adds a new preshared secret.
	 * 
	 * @param this				calling object
	 * @param type				type of identification
	 * @param id_string			identification as string
	 * @param preshared_secret	preshared secret as string
	 */
	void (*add_new_preshared_secret) (private_starter_configuration_t *this,id_type_t type, char *id_string, char *preshared_secret);
	
	/**
	 * Adds a new rsa private key.
	 * 
	 * @param this				calling object
	 * @param type				type of identification
	 * @param id_string			identification as string
	 * @param key_pos			location of key
	 * @param key_len			length of key
	 */
	void (*add_new_rsa_private_key) (private_starter_configuration_t *this,id_type_t type, char *id_string, u_int8_t *key_pos, size_t key_len);
	
	/**
	 * Adds a new rsa public key.
	 * 
	 * @param this				calling object
	 * @param type				type of identification
	 * @param id_string			identification as string
	 * @param key_pos			location of key
	 * @param key_len			length of key
	 */
	void (*add_new_rsa_public_key) (private_starter_configuration_t *this,id_type_t type, char *id_string, u_int8_t *key_pos, size_t key_len);
	
	void (*whack_receive) (private_starter_configuration_t *this);
};

/**
 * Implementation of private_starter_configuration_t.listen.
 */
static void whack_receive(private_starter_configuration_t *this)
{
	u_int8_t buffer[5000];
	struct sockaddr_un whackaddr;
	int whackaddrlen = sizeof(whackaddr);
	ssize_t n;
	int whackfd;
	
	while (1)
	{
		whackfd = accept(this->socket, (struct sockaddr *)&whackaddr, &whackaddrlen);
	
		if (whackfd < 0)
		{
			this->logger->log(this->logger, ERROR, "accept() failed in whack_handle()");
			continue;
		}
		if (fcntl(whackfd, F_SETFD, FD_CLOEXEC) < 0)
		{
			this->logger->log(this->logger, ERROR, "failed to set CLOEXEC in whack_handle()");
			close(whackfd);
			continue;
		}
	
		n = read(whackfd, &buffer, sizeof(buffer));
	
		if (n == -1)
		{
			this->logger->log(this->logger, ERROR, "read() failed in whack_handle()");
			close(whackfd);
			continue;
		}
		this->logger->log_bytes(this->logger, CONTROL, "Whackinput", buffer, n);
	}
}


/**
 * Implementation of starter_configuration_t.get_init_config_for_host.
 */
static status_t get_init_config_for_host (private_starter_configuration_t *this, host_t *my_host, host_t *other_host,init_config_t **init_config)
{
	iterator_t *iterator;
	status_t status = NOT_FOUND;
	
	iterator = this->configurations->create_iterator(this->configurations,TRUE);
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "getting config for hosts %s - %s", 
						my_host->get_address(my_host), other_host->get_address(other_host));
	
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
			this->logger->log(this->logger, CONTROL|LEVEL2, "config entry with remote host %s", 
						config_other_host->get_address(config_other_host));
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
 * Implementation of starter_configuration_t.get_init_config_for_name.
 */
static status_t get_init_config_for_name (private_starter_configuration_t *this, char *name, init_config_t **init_config)
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
 * Implementation of starter_configuration_t.get_sa_config_for_name.
 */
static status_t get_sa_config_for_name (private_starter_configuration_t *this, char *name, sa_config_t **sa_config)
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
 * Implementation of starter_configuration_t.get_sa_config_for_init_config_and_id.
 */
static status_t get_sa_config_for_init_config_and_id (private_starter_configuration_t *this, init_config_t *init_config, identification_t *other_id, identification_t *my_id,sa_config_t **sa_config)
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
 * Implementation of private_starter_configuration_t.add_new_configuration.
 */
static void add_new_configuration (private_starter_configuration_t *this, char *name, init_config_t *init_config, sa_config_t *sa_config)
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

	this->configurations->insert_last(this->configurations,configuration_entry_create(name,init_config,sa_config));
}

/**
 * Implementation of private_starter_configuration_t.add_new_preshared_secret.
 */
static void add_new_preshared_secret (private_starter_configuration_t *this,id_type_t type, char *id_string, char *preshared_secret)
{
	preshared_secret_entry_t *entry = allocator_alloc_thing(preshared_secret_entry_t);
	
	entry->identification = identification_create_from_string(type,id_string);
	entry->preshared_secret.len = strlen(preshared_secret) + 1;
	entry->preshared_secret.ptr = allocator_alloc(entry->preshared_secret.len);
	memcpy(entry->preshared_secret.ptr,preshared_secret,entry->preshared_secret.len);
	
	this->preshared_secrets->insert_last(this->preshared_secrets,entry);
}

/**
 * Implementation of private_starter_configuration_t.add_new_preshared_secret.
 */
static void add_new_rsa_public_key (private_starter_configuration_t *this, id_type_t type, char *id_string, u_int8_t* key_pos, size_t key_len)
{
	chunk_t key;
	key.ptr = key_pos;
	key.len = key_len;
	
	rsa_public_key_entry_t *entry = allocator_alloc_thing(rsa_public_key_entry_t);
	
	entry->identification = identification_create_from_string(type,id_string);
	entry->public_key = rsa_public_key_create();
	entry->public_key->set_key(entry->public_key, key);
	
	this->rsa_public_keys->insert_last(this->rsa_public_keys, entry);
}

/**
 * Implementation of private_starter_configuration_t.add_new_preshared_secret.
 */
static void add_new_rsa_private_key (private_starter_configuration_t *this, id_type_t type, char *id_string, u_int8_t* key_pos, size_t key_len)
{
	chunk_t key;
	key.ptr = key_pos;
	key.len = key_len;
	
	rsa_private_key_entry_t *entry = allocator_alloc_thing(rsa_private_key_entry_t);
	
	entry->identification = identification_create_from_string(type,id_string);
	entry->private_key = rsa_private_key_create();
	entry->private_key->set_key(entry->private_key, key);
	
	this->rsa_private_keys->insert_last(this->rsa_private_keys, entry);
}

/**
 * Implementation of starter_configuration_t.get_shared_secret.
 */
static status_t get_shared_secret(private_starter_configuration_t *this, identification_t *identification, chunk_t *preshared_secret)
{
	iterator_t *iterator;
	
	iterator = this->preshared_secrets->create_iterator(this->preshared_secrets,TRUE);
	while (iterator->has_next(iterator))
	{
		preshared_secret_entry_t *entry;
		iterator->current(iterator,(void **) &entry);
		if (entry->identification->equals(entry->identification,identification))
		{
			*preshared_secret = entry->preshared_secret;
			iterator->destroy(iterator);
			return SUCCESS;
		}
	}
	iterator->destroy(iterator);
	return NOT_FOUND;
}

/**
 * Implementation of starter_configuration_t.get_shared_secret.
 */
static status_t get_rsa_public_key(private_starter_configuration_t *this, identification_t *identification, rsa_public_key_t **public_key)
{
	iterator_t *iterator;
	
	iterator = this->rsa_public_keys->create_iterator(this->rsa_public_keys,TRUE);
	while (iterator->has_next(iterator))
	{
		rsa_public_key_entry_t *entry;
		iterator->current(iterator,(void **) &entry);
		if (entry->identification->equals(entry->identification,identification))
		{
			*public_key = entry->public_key;
			iterator->destroy(iterator);
			return SUCCESS;
		}
	}
	iterator->destroy(iterator);
	return NOT_FOUND;
}

/**
 * Implementation of starter_configuration_t.get_shared_secret.
 */
static status_t get_rsa_private_key(private_starter_configuration_t *this, identification_t *identification, rsa_private_key_t **private_key)
{
	iterator_t *iterator;
	
	iterator = this->rsa_private_keys->create_iterator(this->rsa_private_keys,TRUE);
	while (iterator->has_next(iterator))
	{
		rsa_private_key_entry_t *entry;
		iterator->current(iterator,(void **) &entry);
		if (entry->identification->equals(entry->identification,identification))
		{
			*private_key = entry->private_key;
			iterator->destroy(iterator);
			return SUCCESS;
		}
	}
	iterator->destroy(iterator);
	return NOT_FOUND;
}

/**
 * Implementation of starter_configuration_t.get_retransmit_timeout.
 */
static status_t get_retransmit_timeout (private_starter_configuration_t *this, u_int32_t retransmit_count, u_int32_t *timeout)
{
	int new_timeout = this->first_retransmit_timeout, i;
	if ((retransmit_count > this->max_retransmit_count) && (this->max_retransmit_count != 0))
	{
		return FAILED;
	}
	

	for (i = 0; i < retransmit_count; i++)
	{
		new_timeout *= 2;
	}
	
	*timeout = new_timeout;
	
	return SUCCESS;
}

/**
 * Implementation of starter_configuration_t.get_half_open_ike_sa_timeout.
 */
static u_int32_t get_half_open_ike_sa_timeout (private_starter_configuration_t *this)
{
	return this->half_open_ike_sa_timeout;
}

/**
 * Implementation of starter_configuration_t.destroy.
 */
static void destroy(private_starter_configuration_t *this)
{
	this->logger->log(this->logger,CONTROL | LEVEL1, "Going to destroy configuration backend ");

	this->logger->log(this->logger,CONTROL | LEVEL2, "Destroy configuration entries");
	while (this->configurations->get_count(this->configurations) > 0)
	{
		configuration_entry_t *entry;
		this->configurations->remove_first(this->configurations,(void **) &entry);
		entry->destroy(entry);
	}
	this->configurations->destroy(this->configurations);

	this->logger->log(this->logger,CONTROL | LEVEL2, "Destroy sa_config_t objects");	
	while (this->sa_configs->get_count(this->sa_configs) > 0)
	{
		sa_config_t *sa_config;
		this->sa_configs->remove_first(this->sa_configs,(void **) &sa_config);
		sa_config->destroy(sa_config);
	}

	this->sa_configs->destroy(this->sa_configs);
	
	this->logger->log(this->logger,CONTROL | LEVEL2, "Destroy init_config_t objects");
	while (this->init_configs->get_count(this->init_configs) > 0)
	{
		init_config_t *init_config;
		this->init_configs->remove_first(this->init_configs,(void **) &init_config);
		init_config->destroy(init_config);
	}
	this->init_configs->destroy(this->init_configs);
	
	while (this->preshared_secrets->get_count(this->preshared_secrets) > 0)
	{
		preshared_secret_entry_t *entry;
		this->preshared_secrets->remove_first(this->preshared_secrets,(void **) &entry);
		entry->identification->destroy(entry->identification);
		allocator_free_chunk(&(entry->preshared_secret));
		allocator_free(entry);
	}
	this->preshared_secrets->destroy(this->preshared_secrets);

	this->logger->log(this->logger,CONTROL | LEVEL2, "Destroy rsa private keys");	
	while (this->rsa_private_keys->get_count(this->rsa_private_keys) > 0)
	{
		rsa_private_key_entry_t *entry;
		this->rsa_private_keys->remove_first(this->rsa_private_keys,(void **) &entry);
		entry->identification->destroy(entry->identification);
		entry->private_key->destroy(entry->private_key);
		allocator_free(entry);
	}
	this->rsa_private_keys->destroy(this->rsa_private_keys);

	this->logger->log(this->logger,CONTROL | LEVEL2, "Destroy rsa public keys");
	while (this->rsa_public_keys->get_count(this->rsa_public_keys) > 0)
	{
		rsa_public_key_entry_t *entry;
		this->rsa_public_keys->remove_first(this->rsa_public_keys,(void **) &entry);
		entry->identification->destroy(entry->identification);
		entry->public_key->destroy(entry->public_key);
		allocator_free(entry);
	}
	this->rsa_public_keys->destroy(this->rsa_public_keys);
		
	this->logger->log(this->logger,CONTROL | LEVEL2, "Destroy assigned logger");
	charon->logger_manager->destroy_logger(charon->logger_manager,this->logger);
	close(this->socket);
	unlink(socket_addr.sun_path);
	allocator_free(this);
}

/*
 * Described in header-file
 */
starter_configuration_t *starter_configuration_create()
{
	private_starter_configuration_t *this = allocator_alloc_thing(private_starter_configuration_t);
	mode_t old;
	bool on = TRUE;

	/* public functions */
	this->public.configuration_interface.destroy = (void(*)(configuration_t*))destroy;
	this->public.configuration_interface.get_init_config_for_name = (status_t (*) (configuration_t *, char *, init_config_t **)) get_init_config_for_name;
	this->public.configuration_interface.get_init_config_for_host = (status_t (*) (configuration_t *, host_t *, host_t *,init_config_t **)) get_init_config_for_host;
	this->public.configuration_interface.get_sa_config_for_name =(status_t (*) (configuration_t *, char *, sa_config_t **)) get_sa_config_for_name;
	this->public.configuration_interface.get_sa_config_for_init_config_and_id =(status_t (*) (configuration_t *, init_config_t *, identification_t *, identification_t *,sa_config_t **)) get_sa_config_for_init_config_and_id;
	this->public.configuration_interface.get_retransmit_timeout = (status_t (*) (configuration_t *, u_int32_t retransmit_count, u_int32_t *timeout))get_retransmit_timeout;
	this->public.configuration_interface.get_half_open_ike_sa_timeout = (u_int32_t (*) (configuration_t *)) get_half_open_ike_sa_timeout;
	this->public.configuration_interface.get_shared_secret = (status_t (*) (configuration_t *, identification_t *, chunk_t *))get_shared_secret;
	this->public.configuration_interface.get_rsa_private_key = (status_t (*) (configuration_t *, identification_t *, rsa_private_key_t**))get_rsa_private_key;
	this->public.configuration_interface.get_rsa_public_key = (status_t (*) (configuration_t *, identification_t *, rsa_public_key_t**))get_rsa_public_key;
	
	/* private functions */
	this->add_new_configuration = add_new_configuration;
	this->add_new_preshared_secret = add_new_preshared_secret;
	this->add_new_rsa_public_key = add_new_rsa_public_key;
	this->add_new_rsa_private_key = add_new_rsa_private_key;
	this->whack_receive = whack_receive;
	
	this->logger = charon->logger_manager->create_logger(charon->logger_manager,CONFIG,NULL);
	
	/* set up unix socket */
	this->socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (this->socket == -1)
	{
		this->logger->log(this->logger, ERROR, "could not create whack socket");
		charon->logger_manager->destroy_logger(charon->logger_manager,this->logger);
		allocator_free(this);
		return NULL;
	}
	if (fcntl(this->socket, F_SETFD, FD_CLOEXEC) < 0)
	{
		this->logger->log(this->logger, ERROR, "could not FD_CLOEXEC on whack socket");
		charon->logger_manager->destroy_logger(charon->logger_manager,this->logger);
		close(this->socket);
		allocator_free(this);
		return NULL;
	}
	if (setsockopt(this->socket, SOL_SOCKET, SO_REUSEADDR, (const void *)&on, sizeof(on)) < 0)
	
	old = umask(~S_IRWXU);
	if (bind(this->socket, (struct sockaddr *)&socket_addr, sizeof(socket_addr)) < 0)
	{
		this->logger->log(this->logger, ERROR, "could not bind whack socket: %s", strerror(errno));
		charon->logger_manager->destroy_logger(charon->logger_manager,this->logger);
		close(this->socket);
		allocator_free(this);
		return NULL;
	}
	umask(old);
	
	if (listen(this->socket, 0) < 0)
	{
		this->logger->log(this->logger, ERROR, "could not listen on whack socket: %s", strerror(errno));
		charon->logger_manager->destroy_logger(charon->logger_manager,this->logger);
		close(this->socket);
		unlink(socket_addr.sun_path);
		allocator_free(this);
		return NULL;
	}
	
	/* start a thread reading from the socket */
	if (pthread_create(&(this->assigned_thread), NULL, (void*(*)(void*))this->whack_receive, this) != 0)
	{
		this->logger->log(this->logger, ERROR, "Could not spawn whack thread");
		charon->logger_manager->destroy_logger(charon->logger_manager, this->logger);
		close(this->socket);
		unlink(socket_addr.sun_path);
		allocator_free(this);
	}
	
	/* private variables */
	this->configurations = linked_list_create();
	this->sa_configs = linked_list_create();
	this->init_configs = linked_list_create();
	this->preshared_secrets = linked_list_create();
	this->rsa_private_keys = linked_list_create();
	this->rsa_public_keys = linked_list_create();
	this->max_retransmit_count = MAX_RETRANSMIT_COUNT;
	this->first_retransmit_timeout = RETRANSMIT_TIMEOUT;
	this->half_open_ike_sa_timeout = HALF_OPEN_IKE_SA_TIMEOUT;
	
	return (&this->public);
}
