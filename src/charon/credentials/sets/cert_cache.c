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

#include "cert_cache.h"

#include <daemon.h>
#include <utils/linked_list.h>

#define CACHE_LIMIT 30

typedef struct private_cert_cache_t private_cert_cache_t;
typedef struct relation_t relation_t;

/**
 * private data of cert_cache
 */
struct private_cert_cache_t {

	/**
	 * public functions
	 */
	cert_cache_t public;
	
	/**
	 * list of trusted subject-issuer relations, as relation_t
	 */
	linked_list_t *relations;
};

/**
 * A trusted relation between subject and issuer
 */
struct relation_t {
	/** subject of this relation */
	certificate_t *subject;
	/** issuer of this relation */
	certificate_t *issuer;
	/** time of last use */
	time_t last_use;
};

/**
 * destroy a relation_t structure
 */
static void relation_destroy(relation_t *this)
{
	this->subject->destroy(this->subject);
	this->issuer->destroy(this->issuer);
	free(this);
}

/**
 * Implementation of cert_cache_t.issued_by.
 */
static bool issued_by(private_cert_cache_t *this,
					  certificate_t *subject, certificate_t *issuer)
{
	relation_t *found = NULL, *current, *oldest = NULL;
	enumerator_t *enumerator;
	
	/* lookup cache */
	enumerator = this->relations->create_enumerator(this->relations);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (current->subject == subject && current->issuer == issuer)
		{
			current->last_use = time(NULL);
			found = current;
			break;
		}
		if (oldest == NULL || oldest->last_use <= current->last_use)
		{
			oldest = current;
		}
	}
	enumerator->destroy(enumerator);
	if (found)
	{
		return TRUE;
	}
	/* no cache hit, check signature */
	if (!subject->issued_by(subject, issuer))
	{
		return FALSE;
	}
	/* cache if good, respect cache limit */
	found = malloc_thing(relation_t);
	found->subject = subject->get_ref(subject);
	found->issuer = issuer->get_ref(issuer);
	found->last_use = time(NULL);
	if (this->relations->get_count(this->relations) > CACHE_LIMIT && oldest)
	{
		this->relations->remove(this->relations, oldest, NULL);
		relation_destroy(oldest);
	}
	this->relations->insert_last(this->relations, found);
	return TRUE;
}

/**
 * data associated to a cert enumeration 
 */
typedef struct {
	/** type of requested certificate */
	certificate_type_t cert;
	/** type of requested key */
	key_type_t key;
	/** ID to get a cert from */
	identification_t *id;
} cert_data_t;

/**
 * filter function for certs enumerator
 */
static bool certs_filter(cert_data_t *data, relation_t **in, certificate_t **out)
{
	public_key_t *public;
	certificate_t *cert;
	
	cert = (*in)->subject;
	if ((data->cert == CERT_ANY || cert->get_type(cert) == data->cert) &&
		(!data->id || cert->has_subject(cert, data->id)))
	{
		if (data->key == KEY_ANY)
		{
			*out = cert;
			return TRUE;
		}
		public = cert->get_public_key(cert);
		if (public)
		{
			if (public->get_type(public) == data->key)
			{
				public->destroy(public);
				*out = cert;
				return TRUE;
			}
			public->destroy(public);
		}
	}
	return FALSE;
}

/**
 * implementation of credential_set_t.create_cert_enumerator
 */
static enumerator_t *create_enumerator(private_cert_cache_t *this,
									   certificate_type_t cert, key_type_t key, 
									   identification_t *id, bool trusted)
{
	cert_data_t *data;
	
	if (trusted)
	{
		return NULL;
	}
	data = malloc_thing(cert_data_t);
	data->cert = cert;
	data->key = key;
	data->id = id;
	
	return enumerator_create_filter(
							this->relations->create_enumerator(this->relations),
							(void*)certs_filter, data, (void*)free);
}

/**
 * Implementation of cert_cache_t.flush.
 */
static void flush(private_cert_cache_t *this, certificate_type_t type)
{
	enumerator_t *enumerator;
	relation_t *relation;
	
	enumerator = this->relations->create_enumerator(this->relations);
	while (enumerator->enumerate(enumerator, &relation))
	{
		if (type == CERT_ANY ||
			type == relation->subject->get_type(relation->subject))
		{
			this->relations->remove_at(this->relations, enumerator);
			relation_destroy(relation);
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Implementation of cert_cache_t.destroy
 */
static void destroy(private_cert_cache_t *this)
{
	this->relations->destroy_function(this->relations, (void*)relation_destroy);
	free(this);
}

/*
 * see header file
 */
cert_cache_t *cert_cache_create()
{
	private_cert_cache_t *this = malloc_thing(private_cert_cache_t);
	
	this->public.set.create_private_enumerator = (void*)return_null;
	this->public.set.create_cert_enumerator = (void*)create_enumerator;
	this->public.set.create_shared_enumerator = (void*)return_null;
	this->public.set.create_cdp_enumerator = (void*)return_null;
	this->public.issued_by = (bool(*)(cert_cache_t*, certificate_t *subject, certificate_t *issuer))issued_by;
	this->public.flush = (void(*)(cert_cache_t*, certificate_type_t type))flush;
	this->public.destroy = (void(*)(cert_cache_t*))destroy;
	
	this->relations = linked_list_create();
	
	return &this->public;
}

