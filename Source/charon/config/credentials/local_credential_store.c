/**
 * @file local_credential_store.c
 * 
 * @brief Implementation of local_credential_store_t.
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

#include <sys/stat.h>
#include <dirent.h>

#include "local_credential_store.h"

#include <utils/linked_list.h>
#include <utils/logger_manager.h>
#include <crypto/x509.h>


typedef struct key_entry_t key_entry_t;

/**
 * Private key with an associated ID to find it
 */
struct key_entry_t {
	
	/**
	 * ID, as added
	 */
	identification_t *id;
	
	/**
	 * Associated rsa private key
	 */
	rsa_private_key_t *key;
};


typedef struct private_local_credential_store_t private_local_credential_store_t;

/**
 * Private data of an local_credential_store_t object
 */
struct private_local_credential_store_t {

	/**
	 * Public part
	 */
	local_credential_store_t public;
	
	/**
	 * list of key_entry_t's with private keys
	 */
	linked_list_t *private_keys;
	
	/**
	 * list of x509 certificates with public keys
	 */
	linked_list_t *certificates;
	
	/**
	 * Assigned logger
	 */
	logger_t *logger;
};


/**
 * Implementation of credential_store_t.get_shared_secret.
 */	
static status_t get_shared_secret(private_local_credential_store_t *this, identification_t *identification, chunk_t *preshared_secret)
{
	return FAILED;
}

/**
 * Implementation of credential_store_t.get_rsa_public_key.
 */
static rsa_public_key_t * get_rsa_public_key(private_local_credential_store_t *this, identification_t *identification)
{
	x509_t *current;
	rsa_public_key_t *found = NULL;
	iterator_t *iterator;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Looking for public key for %s",
					  identification->get_string(identification));
	iterator = this->certificates->create_iterator(this->certificates, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current);
		identification_t *stored = current->get_subject(current);
		this->logger->log(this->logger, CONTROL|LEVEL2, "there is one for %s",
						  stored->get_string(stored));
		if (identification->equals(identification, stored))
		{
			found = current->get_public_key(current);
			break;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implementation of credential_store_t.get_rsa_private_key.
 */
static rsa_private_key_t *get_rsa_private_key(private_local_credential_store_t *this, identification_t *identification)
{
	rsa_private_key_t *found = NULL;
	key_entry_t *current;
	iterator_t *iterator;
	
	iterator = this->private_keys->create_iterator(this->private_keys, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current);
		if (identification->equals(identification, current->id))
		{
			found = current->key->clone(current->key);
			break;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implements local_credential_store_t.load_private_keys
 */
static void load_certificates(private_local_credential_store_t *this, char *path)
{
	struct dirent* entry;
	struct stat stb;
	DIR* dir;
	x509_t *cert;
	
	dir = opendir(path);
	if (dir == NULL) {
		this->logger->log(this->logger, ERROR, "error opening certificate directory \"%s\"", path);
		return;
	}
	while ((entry = readdir(dir)) != NULL)
	{
		char file[256];
		snprintf(file, sizeof(file), "%s/%s", path, entry->d_name);
		
		if (stat(file, &stb) == -1)
		{
			continue;
		}
		/* try to parse all regular files */
		if (stb.st_mode & S_IFREG)
		{
			cert = x509_create_from_file(file);
			if (cert)
			{
				this->certificates->insert_last(this->certificates, (void*)cert);
				this->logger->log(this->logger, CONTROL|LEVEL1, "loaded certificate \"%s\"", file);
			}
			else
			{
				this->logger->log(this->logger, ERROR, "certificate \"%s\" invalid, skipped", file);
			}
		}
	}
	closedir(dir);
}

/**
 * Query the ID for a private key, by doing a lookup in the certificates
 */
static identification_t *get_id_for_private_key(private_local_credential_store_t *this, rsa_private_key_t *private_key)
{
	iterator_t *iterator;
	x509_t *cert;
	identification_t *found = NULL;
	rsa_public_key_t *public_key;
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "Getting ID for a private key...");
	
	iterator = this->certificates->create_iterator(this->certificates, TRUE);
	while (!found && iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&cert);
		public_key = cert->get_public_key(cert);
		if (public_key)
		{
			if (private_key->belongs_to(private_key, public_key))
			{
				this->logger->log(this->logger, CONTROL|LEVEL2, "found a match");
				found = cert->get_subject(cert);
				found = found->clone(found);
			}
			else
			{
				this->logger->log(this->logger, CONTROL|LEVEL3, "this one did not match");
			}
			public_key->destroy(public_key);
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implements local_credential_store_t.load_private_keys
 */
static void load_private_keys(private_local_credential_store_t *this, char *path)
{
	struct dirent* entry;
	struct stat stb;
	DIR* dir;
	rsa_private_key_t *key;
	
	dir = opendir(path);
	if (dir == NULL) {
		this->logger->log(this->logger, ERROR, "error opening private key directory \"%s\"", path);
		return;
	}
	while ((entry = readdir(dir)) != NULL)
	{
		char file[256];
		snprintf(file, sizeof(file), "%s/%s", path, entry->d_name);
		
		if (stat(file, &stb) == -1)
		{
			continue;
		}
		/* try to parse all regular files */
		if (stb.st_mode & S_IFREG)
		{
			key = rsa_private_key_create_from_file(file, NULL);
			if (key)
			{
				key_entry_t *entry;
				identification_t *id = get_id_for_private_key(this, key);
				if (!id)
				{
					this->logger->log(this->logger, ERROR, 
									  "no certificate found for private key \"%s\", skipped", file);
					key->destroy(key);
					continue;
				}
				entry = malloc_thing(key_entry_t);
				entry->key = key;
				entry->id = id;
				this->private_keys->insert_last(this->private_keys, (void*)entry);
				this->logger->log(this->logger, CONTROL|LEVEL1, "loaded private key \"%s\"", file);
			}
			else
			{
				this->logger->log(this->logger, ERROR, "private key \"%s\" invalid, skipped", file);
			}
		}
	}
	closedir(dir);
}

/**
 * Implementation of credential_store_t.destroy.
 */
static void destroy(private_local_credential_store_t *this)
{
	x509_t *certificate;
	key_entry_t *key_entry;
	
	while (this->certificates->remove_last(this->certificates, (void**)&certificate) == SUCCESS)
	{
		certificate->destroy(certificate);
	}
	this->certificates->destroy(this->certificates);
	while (this->private_keys->remove_last(this->private_keys, (void**)&key_entry) == SUCCESS)
	{
		key_entry->id->destroy(key_entry->id);
		key_entry->key->destroy(key_entry->key);
		free(key_entry);
	}
	this->private_keys->destroy(this->private_keys);
	free(this);
}

/**
 * Described in header.
 */
local_credential_store_t * local_credential_store_create()
{
	private_local_credential_store_t *this = malloc_thing(private_local_credential_store_t);

	this->public.credential_store.get_shared_secret = (status_t(*)(credential_store_t*,identification_t*,chunk_t*))get_shared_secret;
	this->public.credential_store.get_rsa_private_key = (rsa_private_key_t*(*)(credential_store_t*,identification_t*))get_rsa_private_key;
	this->public.credential_store.get_rsa_public_key = (rsa_public_key_t*(*)(credential_store_t*,identification_t*))get_rsa_public_key;
	this->public.load_certificates = (void(*)(local_credential_store_t*,char*))load_certificates;
	this->public.load_private_keys = (void(*)(local_credential_store_t*,char*))load_private_keys;
	this->public.credential_store.destroy = (void(*)(credential_store_t*))destroy;
	
	/* private variables */
	this->private_keys = linked_list_create();
	this->certificates = linked_list_create();
	this->logger = logger_manager->get_logger(logger_manager, CONFIG);

	return (&this->public);
}
