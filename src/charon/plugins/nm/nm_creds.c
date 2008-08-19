/*
 * Copyright (C) 2008 Martin Willi
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
 *
 * $Id$
 */

#define _GNU_SOURCE
#include <pthread.h>

#include "nm_creds.h"

#include <daemon.h>

typedef struct private_nm_creds_t private_nm_creds_t;

/**
 * private data of nm_creds
 */
struct private_nm_creds_t {

	/**
	 * public functions
	 */
	nm_creds_t public;
	
	/**
	 * gateway certificate
	 */
	certificate_t *cert;
	
	/**
	 * User password
	 */
	char *pass;
	
	/**
	 * read/write lock
	 */
	pthread_rwlock_t lock;
};

/**
 * Implements credential_set_t.create_cert_enumerator
 */
static enumerator_t* create_cert_enumerator(private_nm_creds_t *this,
							certificate_type_t cert, key_type_t key,
							identification_t *id, bool trusted)
{
	if (!this->cert ||
		(cert != CERT_ANY && cert != this->cert->get_type(this->cert)))
	{
		return NULL;
	}
	return enumerator_create_cleaner(enumerator_create_single(this->cert, NULL),
									 (void*)pthread_rwlock_unlock, &this->lock);
}

/**
 * Implements credential_set_t.create_cert_enumerator
 */
static enumerator_t* create_shared_enumerator(private_nm_creds_t *this, 
							shared_key_type_t type,	identification_t *me,
							identification_t *other)
{
	shared_key_t *key;

	if (!this->pass || (type != SHARED_EAP && type != SHARED_IKE))
	{
		return NULL;
	}
	key = shared_key_create(type, chunk_clone(
								chunk_create(this->pass, strlen(this->pass))));
	return enumerator_create_cleaner(
						enumerator_create_single(key, (void*)key->destroy),
						(void*)pthread_rwlock_unlock, &this->lock);
}

/**
 * Implementation of nm_creds_t.set_certificate
 */
static void set_certificate(private_nm_creds_t *this, certificate_t *cert)
{
	pthread_rwlock_wrlock(&this->lock);
	DESTROY_IF(this->cert);
	this->cert = cert;
	pthread_rwlock_unlock(&this->lock);
}

/**
 * Implementation of nm_creds_t.set_password
 */
static void set_password(private_nm_creds_t *this, char *password)
{
	pthread_rwlock_wrlock(&this->lock);
	free(this->pass);
	this->pass = strdup(password);
	pthread_rwlock_unlock(&this->lock);
}

/**
 * Implementation of nm_creds_t.destroy
 */
static void destroy(private_nm_creds_t *this)
{
	DESTROY_IF(this->cert);
	free(this->pass);
	pthread_rwlock_destroy(&this->lock);
	free(this);
}

/*
 * see header file
 */
nm_creds_t *nm_creds_create()
{
	private_nm_creds_t *this = malloc_thing(private_nm_creds_t);
	
	this->public.set.create_private_enumerator = (void*)return_null;
	this->public.set.create_cert_enumerator = (void*)create_cert_enumerator;
	this->public.set.create_shared_enumerator = (void*)create_shared_enumerator;
	this->public.set.create_cdp_enumerator = (void*)return_null;
	this->public.set.cache_cert = (void*)nop;
	this->public.set_certificate = (void(*)(nm_creds_t*, certificate_t *cert))set_certificate;
	this->public.set_password = (void(*)(nm_creds_t*, char *password))set_password;
	this->public.destroy = (void(*)(nm_creds_t*))destroy;
	
	pthread_rwlock_init(&this->lock, NULL);
	
	this->cert = NULL;
	this->pass = NULL;
	
	return &this->public;
}

