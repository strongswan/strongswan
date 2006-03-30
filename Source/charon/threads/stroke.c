/**
 * @file stroke.c
 * 
 * @brief Implementation of stroke_t.
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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>

#include "stroke.h"

#include <types.h>
#include <daemon.h>
#include <transforms/certificate.h>
#include <utils/allocator.h>
#include <queues/jobs/initiate_ike_sa_job.h>


struct sockaddr_un socket_addr = { AF_UNIX, STROKE_SOCKET};

typedef struct configuration_entry_t configuration_entry_t;

/**
 * A configuration entry combines a configuration name with a connection
 * and a policy.
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
	connection_t *connection;

	/**
	 * Configuration for all phases after IKE_SA_INIT exchange.
	 */
	policy_t *policy;
	
	/**
	 * Public key of other peer
	 */
	rsa_public_key_t *public_key;
	
	/**
	 * Own private key
	 */
	rsa_private_key_t *private_key;
	
	/**
	 * Destroys a configuration_entry_t
	 */
	void (*destroy) (configuration_entry_t *this);
};

/**
 * Implementation of configuration_entry_t.destroy.
 */
static void configuration_entry_destroy (configuration_entry_t *this)
{
	this->connection->destroy(this->connection);
	this->policy->destroy(this->policy);
	if (this->public_key)
	{
		this->public_key->destroy(this->public_key);
	}
	allocator_free(this->name);
	allocator_free(this);
}

/**
 * Creates a configuration_entry_t object.
 */
static configuration_entry_t * configuration_entry_create(char *name, connection_t* connection, policy_t *policy, 
														  rsa_private_key_t *private_key, rsa_public_key_t *public_key)
{
	configuration_entry_t *entry = allocator_alloc_thing(configuration_entry_t);

	/* functions */
	entry->destroy = configuration_entry_destroy;

	/* private data */
	entry->connection = connection;
	entry->policy = policy;
	entry->public_key = public_key;
	entry->private_key = private_key;
	entry->name = allocator_alloc(strlen(name) + 1);
	strcpy(entry->name, name);
	
	return entry;
}

typedef struct private_stroke_t private_stroke_t;

/**
 * Private data of an stroke_t object.
 */
struct private_stroke_t {

	/**
	 * Public part of stroke_t object.
	 */
	stroke_t public;

	/**
	 * Holding all configurations.
	 */
	linked_list_t *configurations;
	
	/**
	 * The list of RSA private keys accessible through crendial_store_t interface
	 */
	linked_list_t *private_keys;

	/**
	 * Assigned logger_t object.
	 */
	logger_t *logger;
		
	/**
	 * Unix socket to use for communication
	 */
	int socket;
	
	/**
	 * Thread which reads from the socket
	 */
	pthread_t assigned_thread;

	/**
	 * Read from the socket and handle stroke messages
	 */
	void (*stroke_receive) (private_stroke_t *this);
	
	/**
	 * find a connection in the config list by name 
	 */
	connection_t *(*get_connection_by_name) (private_stroke_t *this, char *name);
};

/**
 * Helper function which corrects the string pointers
 * in a stroke_msg_t. Strings in a stroke_msg sent over "wire"
 * contains RELATIVE addresses (relative to the beginning of the
 * stroke_msg). They must be corrected if they reach our address
 * space...
 */
static void pop_string(stroke_msg_t *msg, char **string)
{
	/* check for sanity of string pointer and string */
	if (*string == NULL)
	{
		*string = "";
	}
	else if (string < (char**)msg ||
		string > (char**)msg + sizeof(stroke_msg_t) ||
		*string < (char*)msg->buffer - (u_int)msg ||
		*string > (char*)(u_int)msg->length)
	{
		*string = "(invalid char* in stroke msg)";
	}
	else
	{
		*string = (char*)msg + (u_int)*string;
	}
}

/**
 * Find the private key for a public key
 */
static rsa_private_key_t *find_private_key(private_stroke_t *this, rsa_public_key_t *public_key)
{
	rsa_private_key_t *private_key = NULL;
	iterator_t *iterator;
	
	iterator = this->private_keys->create_iterator(this->private_keys, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&private_key);
		if (private_key->belongs_to(private_key, public_key))
		{
			break;
		}	
	}
	iterator->destroy(iterator);
	return private_key;
}

/**
 * Load all private keys form "/etc/ipsec.d/private/"
 */
static void load_private_keys(private_stroke_t *this)
{
	struct dirent* entry;
	struct stat stb;
	DIR* dir;
	rsa_private_key_t *key;
	
	/* currently only unencrypted binary DER files are loaded */
	dir = opendir(PRIVATE_KEY_DIR);
	if (dir == NULL || chdir(PRIVATE_KEY_DIR) == -1) {
		this->logger->log(this->logger, ERROR, "error opening private key directory \"%s\"", PRIVATE_KEY_DIR);
		return;
	}
	while ((entry = readdir(dir)) != NULL)
	{
		if (stat(entry->d_name, &stb) == -1)
		{
			continue;
		}
		/* try to parse all regular files */
		if (stb.st_mode & S_IFREG)
		{
			key = rsa_private_key_create_from_file(entry->d_name, NULL);
			if (key)
			{
				this->private_keys->insert_last(this->private_keys, (void*)key);
				this->logger->log(this->logger, CONTROL|LEVEL1, "loaded private key \"%s%s\"", 
								  PRIVATE_KEY_DIR, entry->d_name);
			}
			else
			{
				this->logger->log(this->logger, CONTROL|LEVEL1, "private key \"%s%s\" invalid, skipped", 
								  PRIVATE_KEY_DIR, entry->d_name);
			}
		}
	}
	closedir(dir);
}

/**
 * Implementation of private_stroke_t.stroke_receive.
 */
static void stroke_receive(private_stroke_t *this)
{
	stroke_msg_t *msg;
	u_int16_t msg_length;
	struct sockaddr_un strokeaddr;
	int strokeaddrlen = sizeof(strokeaddr);
	ssize_t bytes_read;
	int strokefd;
	
	while (1)
	{
		strokefd = accept(this->socket, (struct sockaddr *)&strokeaddr, &strokeaddrlen);
	
		if (strokefd < 0)
		{
			this->logger->log(this->logger, ERROR, "accepting stroke connection failed");
			continue;
		}
		
		/* peek the length */
		bytes_read = recv(strokefd, &msg_length, sizeof(msg_length), MSG_PEEK);
		if (bytes_read != sizeof(msg_length))
		{
			this->logger->log(this->logger, ERROR, "reading lenght of stroke message failed");
			close(strokefd);
			continue;
		}
		
		/* read message */
		msg = allocator_alloc(msg_length);
		bytes_read = recv(strokefd, msg, msg_length, 0);
		if (bytes_read != msg_length)
		{
			this->logger->log(this->logger, ERROR, "reading stroke message failed");
			close(strokefd);
			continue;
		}
		
		this->logger->log_bytes(this->logger, RAW, "stroke message", (void*)msg, msg_length);
		
		switch (msg->type)
		{
			case STR_INITIATE:
			{
				initiate_ike_sa_job_t *job;
				connection_t *connection;
				
				pop_string(msg, &(msg->initiate.name));
				this->logger->log(this->logger, CONTROL, "received stroke: initiate \"%s\"", msg->initiate.name);
				connection = this->get_connection_by_name(this, msg->initiate.name);
				if (connection == NULL)
				{
					this->logger->log(this->logger, ERROR, "could not find a connection named \"%s\"", msg->initiate.name);
				}
				else
				{
					job = initiate_ike_sa_job_create(connection);
					charon->job_queue->add(charon->job_queue, (job_t*)job);
				}
				break;
			}
			case STR_INSTALL:
			{
				pop_string(msg, &(msg->install.name));
				this->logger->log(this->logger, CONTROL, "received stroke: install \"%s\"", msg->install.name);
				break;
			}
			case STR_ADD_CONN:
			{
				connection_t *connection;
				policy_t *policy;
				identification_t *my_id, *other_id;
				host_t *my_host, *other_host, *my_subnet, *other_subnet;
				proposal_t *proposal;
				traffic_selector_t *my_ts, *other_ts;
				certificate_t *my_cert, *other_cert;
				rsa_private_key_t *private_key = NULL;
				rsa_public_key_t *public_key = NULL;
				
				pop_string(msg, &msg->add_conn.name);
				pop_string(msg, &msg->add_conn.me.address);
				pop_string(msg, &msg->add_conn.other.address);
				pop_string(msg, &msg->add_conn.me.id);
				pop_string(msg, &msg->add_conn.other.id);
				pop_string(msg, &msg->add_conn.me.cert);
				pop_string(msg, &msg->add_conn.other.cert);
				pop_string(msg, &msg->add_conn.me.subnet);
				pop_string(msg, &msg->add_conn.other.subnet);
				
				this->logger->log(this->logger, CONTROL, "received stroke: add connection \"%s\"", msg->add_conn.name);
				
				my_host = host_create(AF_INET, msg->add_conn.me.address, 500);
				if (my_host == NULL)
				{
					this->logger->log(this->logger, ERROR, "received invalid host: %s", msg->add_conn.me.address);
					break;
				}
				other_host = host_create(AF_INET, msg->add_conn.other.address, 500);
				if (other_host == NULL)
				{
					this->logger->log(this->logger, ERROR, "received invalid host: %s", msg->add_conn.other.address);
					my_host->destroy(my_host);
					break;
				}
				my_id = identification_create_from_string(ID_IPV4_ADDR, 
						*msg->add_conn.me.id ? msg->add_conn.me.id : msg->add_conn.me.address);
				if (my_id == NULL)
				{
					this->logger->log(this->logger, ERROR, "received invalid id: %s", msg->add_conn.me.id);
					my_host->destroy(my_host);
					other_host->destroy(other_host);
					break;
				}
				other_id = identification_create_from_string(ID_IPV4_ADDR, 
						*msg->add_conn.other.id ? msg->add_conn.other.id : msg->add_conn.other.address);
				if (other_id == NULL)
				{
					my_host->destroy(my_host);
					other_host->destroy(other_host);
					my_id->destroy(my_id);
					this->logger->log(this->logger, ERROR, "received invalid id: %s", msg->add_conn.other.id);
					break;
				}
				
				my_subnet = host_create(AF_INET, *msg->add_conn.me.subnet ? msg->add_conn.me.subnet : msg->add_conn.me.address, 500);
				if (my_subnet == NULL)
				{
					my_host->destroy(my_host);
					other_host->destroy(other_host);
					my_id->destroy(my_id);
					other_id->destroy(other_id);
					this->logger->log(this->logger, ERROR, "received invalid subnet: %s", msg->add_conn.me.subnet);
					break;
				}
				
				other_subnet = host_create(AF_INET, *msg->add_conn.other.subnet ? msg->add_conn.other.subnet : msg->add_conn.other.address, 500);
				if (other_subnet == NULL)
				{
					my_host->destroy(my_host);
					other_host->destroy(other_host);
					my_id->destroy(my_id);
					other_id->destroy(other_id);
					my_subnet->destroy(my_subnet);
					this->logger->log(this->logger, ERROR, "received invalid subnet: %s", msg->add_conn.me.subnet);
					break;
				}
				
				my_ts = traffic_selector_create_from_subnet(my_subnet, *msg->add_conn.me.subnet ? msg->add_conn.me.subnet_mask : 32);
				my_subnet->destroy(my_subnet);
				other_ts = traffic_selector_create_from_subnet(other_subnet, *msg->add_conn.other.subnet ? msg->add_conn.other.subnet_mask : 32);
				other_subnet->destroy(other_subnet);
				
				if (charon->socket->is_listening_on(charon->socket, other_host))
				{
					this->logger->log(this->logger, CONTROL|LEVEL1, "left is other host, switching");
					
					host_t *tmp_host = my_host;
					identification_t *tmp_id = my_id;
					traffic_selector_t *tmp_ts = my_ts;
					char *tmp_cert = msg->add_conn.me.cert;
					
					my_host = other_host;
					other_host = tmp_host;
					my_id = other_id;
					other_id = tmp_id;
					my_ts = other_ts;
					other_ts = tmp_ts;
					msg->add_conn.me.cert = msg->add_conn.other.cert;
					msg->add_conn.other.cert = tmp_cert;
				}
				else if (charon->socket->is_listening_on(charon->socket, my_host))
				{
					this->logger->log(this->logger, CONTROL|LEVEL1, "left is own host, not switching");
				}
				else
				{
					this->logger->log(this->logger, ERROR, "left nor right host is our, aborting");
					
					my_host->destroy(my_host);
					other_host->destroy(other_host);
					my_id->destroy(my_id);
					other_id->destroy(other_id);
					my_ts->destroy(my_ts);
					other_ts->destroy(other_ts);
					break;
				}
				
				connection = connection_create(my_host, other_host, my_id->clone(my_id), other_id->clone(other_id), 
											   RSA_DIGITAL_SIGNATURE);
				proposal = proposal_create(1);
				proposal->add_algorithm(proposal, PROTO_IKE, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 16);
				proposal->add_algorithm(proposal, PROTO_IKE, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 0);
				proposal->add_algorithm(proposal, PROTO_IKE, INTEGRITY_ALGORITHM, AUTH_HMAC_MD5_96, 0);
				proposal->add_algorithm(proposal, PROTO_IKE, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA1, 0);
				proposal->add_algorithm(proposal, PROTO_IKE, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_MD5, 0);
				proposal->add_algorithm(proposal, PROTO_IKE, DIFFIE_HELLMAN_GROUP, MODP_2048_BIT, 0);
				proposal->add_algorithm(proposal, PROTO_IKE, DIFFIE_HELLMAN_GROUP, MODP_1536_BIT, 0);
				proposal->add_algorithm(proposal, PROTO_IKE, DIFFIE_HELLMAN_GROUP, MODP_1024_BIT, 0);
				proposal->add_algorithm(proposal, PROTO_IKE, DIFFIE_HELLMAN_GROUP, MODP_4096_BIT, 0);
				proposal->add_algorithm(proposal, PROTO_IKE, DIFFIE_HELLMAN_GROUP, MODP_8192_BIT, 0);
				connection->add_proposal(connection, proposal);
				
				policy = policy_create(my_id, other_id);
				proposal = proposal_create(1);
				proposal->add_algorithm(proposal, PROTO_ESP, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 16);
				proposal->add_algorithm(proposal, PROTO_ESP, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 0);
				proposal->add_algorithm(proposal, PROTO_ESP, INTEGRITY_ALGORITHM, AUTH_HMAC_MD5_96, 0);
				policy->add_proposal(policy, proposal);
				policy->add_my_traffic_selector(policy, my_ts);
				policy->add_other_traffic_selector(policy, other_ts);
				
				
				chdir(CERTIFICATE_DIR);
				my_cert = certificate_create_from_file(msg->add_conn.me.cert);
				if (my_cert == NULL)
				{
					this->logger->log(this->logger, ERROR, "loading own certificate \"%s%s\" failed", 
									  CERTIFICATE_DIR, msg->add_conn.me.cert);
				}
				else
				{
					private_key = find_private_key(this, my_cert->get_public_key(my_cert));
					if (private_key)
					{
						this->logger->log(this->logger, CONTROL|LEVEL1, "found private key for certificate \"%s%s\"", 
										  CERTIFICATE_DIR, msg->add_conn.me.cert);
					}
					else
					{
						this->logger->log(this->logger, ERROR, "no private key for certificate \"%s%s\" found", 
										  CERTIFICATE_DIR, msg->add_conn.me.cert);
					}
				}
				other_cert = certificate_create_from_file(msg->add_conn.other.cert);
				if (other_cert == NULL)
				{
					this->logger->log(this->logger, ERROR, "loading peers certificate \"%s%s\" failed", 
									  CERTIFICATE_DIR, msg->add_conn.other.cert);
				}
				else
				{
					public_key = other_cert->get_public_key(other_cert);
					this->logger->log(this->logger, CONTROL|LEVEL1, "loaded certificate \"%s%s\" (%p)", 
									  CERTIFICATE_DIR, msg->add_conn.other.cert, public_key);
					
				}
				
				this->configurations->insert_last(this->configurations, 
						configuration_entry_create(msg->add_conn.name, connection, policy, private_key, public_key));
				
				this->logger->log(this->logger, CONTROL|LEVEL1, "connection \"%s\" added (%d in store)", 
								  msg->add_conn.name,
								  this->configurations->get_count(this->configurations));
				break;
			}
			case STR_DEL_CONN:
			default:
				this->logger->log(this->logger, ERROR, "received invalid stroke");
		}
		
		close(strokefd);
		allocator_free(msg);
	}
}

/**
 * Implementation of connection_store_t.get_connection_by_hosts.
 */
static connection_t *get_connection_by_hosts(connection_store_t *store, host_t *my_host, host_t *other_host)
{
	private_stroke_t *this = (private_stroke_t*)((u_int8_t*)store - offsetof(stroke_t, connections));
	iterator_t *iterator;
	connection_t *found = NULL;
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "getting config for hosts %s - %s", 
					  my_host->get_address(my_host), other_host->get_address(other_host));
	
	iterator = this->configurations->create_iterator(this->configurations,TRUE);
	while (iterator->has_next(iterator))
	{
		configuration_entry_t *entry;
		host_t *config_my_host, *config_other_host;
		
		iterator->current(iterator,(void **) &entry);

		config_my_host = entry->connection->get_my_host(entry->connection);
		config_other_host = entry->connection->get_other_host(entry->connection);

		/* first check if ip is equal */
		if(config_other_host->ip_equals(config_other_host, other_host))
		{
			this->logger->log(this->logger, CONTROL|LEVEL2, "config entry with remote host %s", 
						config_other_host->get_address(config_other_host));
			/* could be right one, check my_host for default route*/
			if (config_my_host->is_default_route(config_my_host))
			{
				found = entry->connection->clone(entry->connection);
				break;
			}
			/* check now if host informations are the same */
			else if (config_my_host->ip_equals(config_my_host,my_host))
			{
				found = entry->connection->clone(entry->connection);
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
				found = entry->connection->clone(entry->connection);
				break;
			}
			/* check now if host informations are the same */
			else if (config_my_host->ip_equals(config_my_host,my_host))
			{
				found = entry->connection->clone(entry->connection);
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
static connection_t *get_connection_by_ids(connection_store_t *store, identification_t *my_id, identification_t *other_id)
{
	private_stroke_t *this = (private_stroke_t*)((u_int8_t*)store - offsetof(stroke_t, connections));
	iterator_t *iterator;
	connection_t *found = NULL;
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "getting config for ids %s - %s", 
					  my_id->get_string(my_id), other_id->get_string(other_id));
	
	iterator = this->configurations->create_iterator(this->configurations,TRUE);
	while (iterator->has_next(iterator))
	{
		configuration_entry_t *entry;
		identification_t *config_my_id, *config_other_id;
		
		iterator->current(iterator,(void **) &entry);
		
		config_my_id = entry->connection->get_my_id(entry->connection);
		config_other_id = entry->connection->get_other_id(entry->connection);

		/* first check if ids are equal 
		* TODO: Add wildcard checks */
		if (config_other_id->equals(config_other_id, other_id) &&
			config_my_id->equals(config_my_id, my_id))
		{
			this->logger->log(this->logger, CONTROL|LEVEL2, "config entry with remote id %s", 
							  config_other_id->get_string(config_other_id));
			found = entry->connection->clone(entry->connection);
			break;
		}
	}
	iterator->destroy(iterator);
	
	return found;
}

/**
 * Implementation of private_stroke_t.get_connection_by_name.
 */
static connection_t *get_connection_by_name(private_stroke_t *this, char *name)
{
	iterator_t *iterator;
	connection_t *found = NULL;
	
	iterator = this->configurations->create_iterator(this->configurations, TRUE);
	while (iterator->has_next(iterator))
	{
		configuration_entry_t *entry;
		iterator->current(iterator,(void **) &entry);

		if (strcmp(entry->name,name) == 0)
		{
			/* found configuration */
			found = entry->connection->clone(entry->connection);
			break;
		}
	}
	iterator->destroy(iterator);
	
	return found;
}

/**
 * Implementation of policy_store_t.get_policy.
 */
static policy_t *get_policy(policy_store_t *store,identification_t *my_id, identification_t *other_id)
{	
	private_stroke_t *this = (private_stroke_t*)((u_int8_t*)store - offsetof(stroke_t, policies));
	iterator_t *iterator;
	policy_t *found = NULL;
	
	iterator = this->configurations->create_iterator(this->configurations, TRUE);
	while (iterator->has_next(iterator))
	{
		configuration_entry_t *entry;
		iterator->current(iterator,(void **) &entry);
		identification_t *config_my_id = entry->policy->get_my_id(entry->policy);
		identification_t *config_other_id = entry->policy->get_other_id(entry->policy);
		
		/* check other host first */
		if (config_other_id->belongs_to(config_other_id, other_id))
		{		
			/* get it if my_id not specified */
			if (my_id == NULL)
			{
				found = entry->policy->clone(entry->policy);
				break;
			}

			if (config_my_id->belongs_to(config_my_id, my_id))
			{
				found = entry->policy->clone(entry->policy);
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
 * Implementation of credential_store_t.get_shared_secret.
 */	
static status_t get_shared_secret(credential_store_t *this, identification_t *identification, chunk_t *preshared_secret)
{
	char *secret = "schluessel\n";
	preshared_secret->ptr = secret;
	preshared_secret->len = strlen(secret) + 1;
	
	*preshared_secret = allocator_clone_chunk(*preshared_secret);
	return SUCCESS;
}

/**
 * Implementation of credential_store_t.get_rsa_public_key.
 */
static status_t get_rsa_public_key(credential_store_t *store, identification_t *identification, rsa_public_key_t **public_key)
{
	private_stroke_t *this = (private_stroke_t*)((u_int8_t*)store - offsetof(stroke_t, credentials));
	iterator_t *iterator;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Looking for public key for %s",
					  identification->get_string(identification));
	iterator = this->configurations->create_iterator(this->configurations, TRUE);
	while (iterator->has_next(iterator))
	{
		configuration_entry_t *config;
		iterator->current(iterator, (void**)&config);
		identification_t *stored = config->policy->get_other_id(config->policy);
		this->logger->log(this->logger, CONTROL|LEVEL2, "there is one for %s",
						  stored->get_string(stored));
		if (identification->equals(identification, stored))
		{
			this->logger->log(this->logger, CONTROL|LEVEL2, "found a match: %p",
							  config->public_key);
			if (config->public_key)
			{
				iterator->destroy(iterator);
				*public_key = config->public_key;
				return SUCCESS;
			}
		}
	}
	iterator->destroy(iterator);
	return NOT_FOUND;
}

/**
 * Implementation of credential_store_t.get_rsa_private_key.
 */
static status_t get_rsa_private_key(credential_store_t *store, identification_t *identification, rsa_private_key_t **private_key)
{
	private_stroke_t *this = (private_stroke_t*)((u_int8_t*)store - offsetof(stroke_t, credentials));
	iterator_t *iterator;
	
	iterator = this->configurations->create_iterator(this->configurations, TRUE);
	while (iterator->has_next(iterator))
	{
		configuration_entry_t *config;
		iterator->current(iterator, (void**)&config);
		identification_t *stored = config->policy->get_my_id(config->policy);
		if (identification->equals(identification, stored))
		{
			if (config->private_key)
			{
				iterator->destroy(iterator);
				*private_key = config->private_key;
				return SUCCESS;
			}
		}
	}
	iterator->destroy(iterator);
	return NOT_FOUND;
}

/**
 * Implementation of stroke_t.destroy.
 */
static void destroy(private_stroke_t *this)
{
	configuration_entry_t *entry;
	rsa_private_key_t *priv_key;
	
	while (this->configurations->remove_first(this->configurations, (void **)&entry) == SUCCESS)
	{
		entry->destroy(entry);
	}
	this->configurations->destroy(this->configurations);
	
	while (this->private_keys->remove_first(this->private_keys, (void **)&priv_key) == SUCCESS)
	{
		priv_key->destroy(priv_key);
	}
	this->private_keys->destroy(this->private_keys);

	close(this->socket);
	unlink(socket_addr.sun_path);
	allocator_free(this);
}

/**
 * Dummy function which does nothing.
 * Used for connection_store_t.destroy and policy_store_t.destroy,
 * since destruction is done in store_t's destructor...
 */
void do_nothing(void *nothing)
{
	return;
}

/*
 * Described in header-file
 */
stroke_t *stroke_create()
{
	private_stroke_t *this = allocator_alloc_thing(private_stroke_t);
	mode_t old;

	/* public functions */
	this->public.connections.get_connection_by_ids = get_connection_by_ids;
	this->public.connections.get_connection_by_hosts = get_connection_by_hosts;
	this->public.connections.destroy = (void (*) (connection_store_t*))do_nothing;
	this->public.policies.get_policy = get_policy;
	this->public.policies.destroy = (void (*) (policy_store_t*))do_nothing;
	this->public.credentials.get_shared_secret = (status_t (*)(credential_store_t*,identification_t*,chunk_t*))get_shared_secret;
	this->public.credentials.get_rsa_public_key = (status_t (*)(credential_store_t*,identification_t*,rsa_public_key_t**))get_rsa_public_key;
	this->public.credentials.get_rsa_private_key = (status_t (*)(credential_store_t*,identification_t*,rsa_private_key_t**))get_rsa_private_key;
	this->public.credentials.destroy = (void (*) (credential_store_t*))do_nothing;
	this->public.destroy = (void (*)(stroke_t*))destroy;
	
	/* private functions */
	this->stroke_receive = stroke_receive;
	this->get_connection_by_name = get_connection_by_name;
	
	this->logger = charon->logger_manager->get_logger(charon->logger_manager, CONFIG);
	
	/* set up unix socket */
	this->socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (this->socket == -1)
	{
		this->logger->log(this->logger, ERROR, "could not create whack socket");
		allocator_free(this);
		return NULL;
	}
	
	old = umask(~S_IRWXU);
	if (bind(this->socket, (struct sockaddr *)&socket_addr, sizeof(socket_addr)) < 0)
	{
		this->logger->log(this->logger, ERROR, "could not bind stroke socket: %s", strerror(errno));
		close(this->socket);
		allocator_free(this);
		return NULL;
	}
	umask(old);
	
	if (listen(this->socket, 0) < 0)
	{
		this->logger->log(this->logger, ERROR, "could not listen on stroke socket: %s", strerror(errno));
		close(this->socket);
		unlink(socket_addr.sun_path);
		allocator_free(this);
		return NULL;
	}
	
	/* start a thread reading from the socket */
	if (pthread_create(&(this->assigned_thread), NULL, (void*(*)(void*))this->stroke_receive, this) != 0)
	{
		this->logger->log(this->logger, ERROR, "Could not spawn stroke thread");
		close(this->socket);
		unlink(socket_addr.sun_path);
		allocator_free(this);
		return NULL;
	}
	
	/* private variables */
	this->configurations = linked_list_create();
	this->private_keys = linked_list_create();
	
	load_private_keys(this);
	
	return (&this->public);
}
