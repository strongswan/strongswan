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
#include <string.h>

#include "local_credential_store.h"

#include <utils/lexparser.h>
#include <utils/linked_list.h>
#include <utils/logger_manager.h>
#include <crypto/x509.h>

#define PATH_BUF	256

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
	 * list of X.509 certificates with public keys
	 */
	linked_list_t *certs;
	
	/**
	 * list of X.509 CA certificates with public keys
	 */
	linked_list_t *ca_certs;
	/**
	 * Assigned logger
	 */
	logger_t *logger;
};


/**
 * Implementation of credential_store_t.get_shared_secret.
 */	
static status_t get_shared_secret(private_local_credential_store_t *this, identification_t *id, chunk_t *secret)
{
	return FAILED;
}

/**
 * Implementation of credential_store_t.get_rsa_public_key.
 */
static rsa_public_key_t * get_rsa_public_key(private_local_credential_store_t *this, identification_t *id)
{
	rsa_public_key_t *found = NULL;

	iterator_t *iterator = this->certs->create_iterator(this->certs, TRUE);

	while (iterator->has_next(iterator))
	{
		x509_t *cert;

		iterator->current(iterator, (void**)&cert);

		if (id->equals(id, cert->get_subject(cert)) || cert->equals_subjectAltName(cert, id))
		{
			found = cert->get_public_key(cert);
			break;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implementation of credential_store_t.get_rsa_private_key.
 */
static rsa_private_key_t* get_rsa_private_key(private_local_credential_store_t *this, rsa_public_key_t *pubkey)
{
	rsa_private_key_t *found = NULL;
	rsa_private_key_t *current;

	iterator_t *iterator = this->private_keys->create_iterator(this->private_keys, TRUE);

	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current);

		if (current->belongs_to(current, pubkey))
		{
			found = current->clone(current);
			break;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implementation of credential_store_t.has_rsa_private_key.
 */
static bool has_rsa_private_key(private_local_credential_store_t *this, rsa_public_key_t *pubkey)
{
	bool found = FALSE;
	rsa_private_key_t *current;

	iterator_t *iterator = this->private_keys->create_iterator(this->private_keys, TRUE);

	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current);

		if (current->belongs_to(current, pubkey))
		{
			found = TRUE;
			break;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implements credential_store_t.add_certificate
 */
static void add_certificate(private_local_credential_store_t *this, x509_t *cert)
{
	bool found = FALSE;

	iterator_t *iterator = this->certs->create_iterator(this->certs, TRUE);

	while (iterator->has_next(iterator))
	{
		x509_t *current_cert;

		iterator->current(iterator, (void**)&current_cert);
		if (cert->equals(cert, current_cert))
		{
			found = TRUE;
			break;
		}
	}
	iterator->destroy(iterator);

	if (found)
	{
		cert->destroy(cert);
	}
	else
	{
		this->certs->insert_last(this->certs, (void*)cert);
	}
}

/**
 * Implements credential_store_t.log_certificates
 */
static void log_certificates(private_local_credential_store_t *this, logger_t *logger, bool utc)
{
	iterator_t *iterator = this->certs->create_iterator(this->certs, TRUE);
	
	if (iterator->get_count(iterator))
	{
		logger->log(logger, CONTROL, "");
		logger->log(logger, CONTROL, "List of X.509 End Entity Certificates:");
		logger->log(logger, CONTROL, "");
	}
	
	while (iterator->has_next(iterator))
	{
		x509_t *cert;
		bool has_key;
		
		iterator->current(iterator, (void**)&cert);
		has_key = has_rsa_private_key(this, cert->get_public_key(cert));
		cert->log_certificate(cert, logger, utc, has_key);
	}
	iterator->destroy(iterator);
}

/**
 * Implements credential_store_t.log_ca_certificates
 */
static void log_ca_certificates(private_local_credential_store_t *this, logger_t *logger, bool utc)
{
	iterator_t *iterator = this->ca_certs->create_iterator(this->ca_certs, TRUE);

	if (iterator->get_count(iterator))
	{
		logger->log(logger, CONTROL, "");
		logger->log(logger, CONTROL, "List of X.509 CA Certificates:");
		logger->log(logger, CONTROL, "");
	}

	while (iterator->has_next(iterator))
	{
		x509_t *cert;

		iterator->current(iterator, (void**)&cert);
		cert->log_certificate(cert, logger, utc, FALSE);
	}
	iterator->destroy(iterator);
}
/**
 * Implements local_credential_store_t.load_ca_certificates
 */
static void load_ca_certificates(private_local_credential_store_t *this, const char *path)
{
	struct dirent* entry;
	struct stat stb;
	DIR* dir;
	x509_t *cert;
	
	this->logger->log(this->logger, CONTROL, "loading ca certificates from '%s/'", path);

	dir = opendir(path);
	if (dir == NULL)
	{
		this->logger->log(this->logger, ERROR, "error opening ca certs directory %s'", path);
		return;
	}

	while ((entry = readdir(dir)) != NULL)
	{
		char file[PATH_BUF];

		snprintf(file, sizeof(file), "%s/%s", path, entry->d_name);
		
		if (stat(file, &stb) == -1)
		{
			continue;
		}
		/* try to parse all regular files */
		if (stb.st_mode & S_IFREG)
		{
			cert = x509_create_from_file(file, "ca certificate");
			if (cert)
			{
				err_t ugh = cert->is_valid(cert, NULL);

				if (ugh != NULL)	
				{
					this->logger->log(this->logger, ERROR, "warning: ca certificate %s", ugh);
				}
				if (cert->is_ca(cert))
				{
					this->ca_certs->insert_last(this->ca_certs, (void*)cert);
				}
				else
				{
					this->logger->log(this->logger, ERROR,
							"  CA basic constraints flag not set, cert discarded");
					cert->destroy(cert);
				}
			}
		}
	}
	closedir(dir);
}

/**
 * Implements local_credential_store_t.load_private_keys
 */
static void load_private_keys(private_local_credential_store_t *this, const char *secretsfile, const char *defaultpath)
{
	FILE *fd = fopen(secretsfile, "r");

	if (fd)
	{
		int bytes;
		int line_nr = 0;
    	chunk_t chunk, src, line;

		this->logger->log(this->logger, CONTROL, "loading secrets from \"%s\"", secretsfile);

		fseek(fd, 0, SEEK_END);
		chunk.len = ftell(fd);
		rewind(fd);
		chunk.ptr = malloc(chunk.len);
		bytes = fread(chunk.ptr, 1, chunk.len, fd);
		fclose(fd);

		src = chunk;

		while (fetchline(&src, &line))
		{
			chunk_t ids, token;

			line_nr++;

			if (!eat_whitespace(&line))
			{
				continue;
			}
			if (!extract_token(&ids, ':', &line))
			{
				this->logger->log(this->logger, ERROR, "line %d: missing ':' separator", line_nr);
				goto error;
			}
			if (!eat_whitespace(&line) || !extract_token(&token, ' ', &line))
			{
				this->logger->log(this->logger, ERROR, "line %d: missing token", line_nr);
				goto error;
			}
			if (match("RSA", &token))
			{
				char path[PATH_BUF];
				chunk_t filename;

				err_t ugh = extract_value(&filename, &line);

				if (ugh != NULL)
				{
					this->logger->log(this->logger, ERROR, "line %d: %s", line_nr, ugh);
					goto error;
				}
				if (filename.len == 0)
				{
					this->logger->log(this->logger, ERROR,
						"line %d: empty filename", line_nr);
					goto error;
				}
				if (*filename.ptr == '/')
				{
					/* absolute path name */
					snprintf(path, sizeof(path), "%.*s", filename.len, filename.ptr);
				}
				else
				{
					/* relative path name */
					snprintf(path, sizeof(path), "%s/%.*s", defaultpath, filename.len, filename.ptr);
				}

				rsa_private_key_t *key = rsa_private_key_create_from_file(path, NULL);
				if (key)
				{
					this->private_keys->insert_last(this->private_keys, (void*)key);
				}
			}
			else if (match("PSK", &token))
			{

			}
			else if (match("PIN", &token))
			{

			}
			else
			{
				this->logger->log(this->logger, ERROR,
					 "line %d: token must be either RSA, PSK, or PIN",
					  line_nr, token.len);
				goto error;
			}
		}
error:
		free(chunk.ptr);
	}
	else
	{
		this->logger->log(this->logger, ERROR, "could not open file '%s'", secretsfile);
	}
}

/**
 * Implementation of credential_store_t.destroy.
 */
static void destroy(private_local_credential_store_t *this)
{
	x509_t *cert;
	rsa_private_key_t *key;
	
	/* destroy cert list */
	while (this->certs->remove_last(this->certs, (void**)&cert) == SUCCESS)
	{
		cert->destroy(cert);
	}
	this->certs->destroy(this->certs);

	/* destroy ca cert list */
	while (this->ca_certs->remove_last(this->ca_certs, (void**)&cert) == SUCCESS)
	{
		cert->destroy(cert);
	}
	this->ca_certs->destroy(this->ca_certs);

    /* destroy private key list */
	while (this->private_keys->remove_last(this->private_keys, (void**)&key) == SUCCESS)
	{
		key->destroy(key);
	}
	this->private_keys->destroy(this->private_keys);

	free(this);
}

/**
 * Described in header.
 */
local_credential_store_t * local_credential_store_create(void)
{
	private_local_credential_store_t *this = malloc_thing(private_local_credential_store_t);

	this->public.credential_store.get_shared_secret = (status_t(*)(credential_store_t*,identification_t*,chunk_t*))get_shared_secret;
	this->public.credential_store.get_rsa_private_key = (rsa_private_key_t*(*)(credential_store_t*,rsa_public_key_t*))get_rsa_private_key;
	this->public.credential_store.has_rsa_private_key = (bool(*)(credential_store_t*,rsa_public_key_t*))has_rsa_private_key;
	this->public.credential_store.get_rsa_public_key = (rsa_public_key_t*(*)(credential_store_t*,identification_t*))get_rsa_public_key;
	this->public.credential_store.add_certificate = (void(*)(credential_store_t*,x509_t*))add_certificate;
	this->public.credential_store.log_certificates = (void(*)(credential_store_t*,logger_t*,bool))log_certificates;
	this->public.credential_store.log_ca_certificates = (void(*)(credential_store_t*,logger_t*,bool))log_ca_certificates;
	this->public.load_ca_certificates = (void(*)(local_credential_store_t*,const char*))load_ca_certificates;
	this->public.load_private_keys = (void(*)(local_credential_store_t*,const char*, const char*))load_private_keys;
	this->public.credential_store.destroy = (void(*)(credential_store_t*))destroy;
	
	/* private variables */
	this->private_keys = linked_list_create();
	this->certs = linked_list_create();
	this->ca_certs = linked_list_create();
	this->logger = logger_manager->get_logger(logger_manager, CONFIG);

	return (&this->public);
}
