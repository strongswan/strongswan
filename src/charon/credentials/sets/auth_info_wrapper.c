/*
 * Copyright (C) 2008 Tobias Brunner
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

#include <daemon.h>

#include "auth_info_wrapper.h"

typedef struct private_auth_info_wrapper_t private_auth_info_wrapper_t;

/**
 * private data of auth_info_wrapper
 */
struct private_auth_info_wrapper_t {

	/**
	 * public functions
	 */
	auth_info_wrapper_t public;
	
	/**
	 * wrapped auth info
	 */
	auth_info_t *auth;
};

/**
 * enumerator for auth_info_wrapper_t.create_cert_enumerator()
 */
typedef struct {
	/** implements enumerator_t */
	enumerator_t public;
	/** inner enumerator from auth_info */
	enumerator_t *inner;
	/** wrapped auth info */
	auth_info_t *auth;
	/** enumerated cert type */
	certificate_type_t cert;
	/** enumerated key type */
	key_type_t key;
	/** enumerated id */
	identification_t *id;
} wrapper_enumerator_t;

/**
 * Tries to fetch a certificate that was supplied as "Hash and URL" (replaces the
 * item's type and value in place).
 */
static bool fetch_cert(wrapper_enumerator_t *enumerator, auth_item_t *type, void **value)
{
	char *url = (char*)*value;
	if (!url)
	{
		/* fetching the certificate previously failed */
		return FALSE;
	}
	
	chunk_t data;
	certificate_t *cert;
	
	DBG1(DBG_CFG, "  fetching certificate from '%s' ...", url);
	if (lib->fetcher->fetch(lib->fetcher, url, &data, FETCH_END) != SUCCESS)
	{
		DBG1(DBG_CFG, "  fetching certificate failed");
		/* we set the item to NULL, so we can skip it */
		enumerator->auth->replace_item(enumerator->inner, *type, NULL);
		return FALSE;
	}
	
	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
					  BUILD_BLOB_ASN1_DER, data, BUILD_END);
	free(data.ptr);
	
	if (!cert)
	{
		DBG1(DBG_CFG, "  parsing fetched certificate failed");
		/* we set the item to NULL, so we can skip it */
		enumerator->auth->replace_item(enumerator->inner, *type, NULL);
		return FALSE;
	}
	
	DBG1(DBG_CFG, "  fetched certificate \"%D\"", cert->get_subject(cert));
	charon->credentials->cache_cert(charon->credentials, cert);
	
	*type = (*type == AUTHN_IM_HASH_URL) ? AUTHN_IM_CERT : AUTHN_SUBJECT_CERT;
	*value = cert;
	enumerator->auth->replace_item(enumerator->inner, *type, cert);
	
	return TRUE;
}

/**
 * enumerate function for wrapper_enumerator_t
 */
static bool enumerate(wrapper_enumerator_t *this, certificate_t **cert)
{
	auth_item_t type;
	certificate_t *current;
	public_key_t *public;

	while (this->inner->enumerate(this->inner, &type, &current))
	{
		if (type == AUTHN_IM_HASH_URL ||
			type == AUTHN_SUBJECT_HASH_URL)
		{
			if (!fetch_cert(this, &type, (void**)&current))
			{
				continue;
			}
		}
		else if (type != AUTHN_SUBJECT_CERT && 
				 type != AUTHN_IM_CERT)
		{
			continue;
		}

		if (this->cert != CERT_ANY && this->cert != current->get_type(current))
		{	/* CERT type requested, but does not match */
			continue;
		}
		public = current->get_public_key(current);
		if (this->key != KEY_ANY && !public)
		{	/* key type requested, but no public key */
			DESTROY_IF(public);
			continue;
		}
		if (this->key != KEY_ANY && public && this->key != public->get_type(public))
		{	/* key type requested, but public key has another type */
			DESTROY_IF(public);
			continue;
		}
		DESTROY_IF(public);
		if (this->id && !current->has_subject(current, this->id))
		{	/* subject requested, but does not match */
			continue;
		}
		*cert = current;
		return TRUE;
	}
	return FALSE;
}

/**
 * destroy function for wrapper_enumerator_t
 */
static void wrapper_enumerator_destroy(wrapper_enumerator_t *this)
{
	this->inner->destroy(this->inner);
	free(this);
}

/**
 * implementation of auth_info_wrapper_t.set.create_cert_enumerator
 */
static enumerator_t *create_enumerator(private_auth_info_wrapper_t *this,
									   certificate_type_t cert, key_type_t key, 
									   identification_t *id, bool trusted)
{
	wrapper_enumerator_t *enumerator;
	
	if (trusted)
	{
		return NULL;
	}
	enumerator = malloc_thing(wrapper_enumerator_t);
	enumerator->auth = this->auth;
	enumerator->cert = cert;
	enumerator->key = key;
	enumerator->id = id;
	enumerator->inner = this->auth->create_item_enumerator(this->auth);
	enumerator->public.enumerate = (void*)enumerate;
	enumerator->public.destroy = (void*)wrapper_enumerator_destroy;
	return &enumerator->public;
}

/**
 * Implementation of auth_info_wrapper_t.destroy
 */
static void destroy(private_auth_info_wrapper_t *this)
{
	free(this);
}

/*
 * see header file
 */
auth_info_wrapper_t *auth_info_wrapper_create(auth_info_t *auth)
{
	private_auth_info_wrapper_t *this = malloc_thing(private_auth_info_wrapper_t);
	
	this->public.set.create_private_enumerator = (void*)return_null;
	this->public.set.create_cert_enumerator = (void*)create_enumerator;
	this->public.set.create_shared_enumerator = (void*)return_null;
	this->public.set.create_cdp_enumerator = (void*)return_null;
	this->public.set.cache_cert = (void*)nop;
	this->public.destroy = (void(*)(auth_info_wrapper_t*))destroy;
	
	this->auth = auth;
	
	return &this->public;
}

