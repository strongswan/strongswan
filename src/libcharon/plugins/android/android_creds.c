/*
 * Copyright (C) 2010 Tobias Brunner
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

#include <keystore_get.h>

#include "android_creds.h"

#include <daemon.h>
#include <threading/rwlock.h>

typedef struct private_android_creds_t private_android_creds_t;

/**
 * Private data of an android_creds_t object
 */
struct private_android_creds_t {

	/**
	 * Public interface
	 */
	android_creds_t public;

	/**
	 * List of trusted certificates, certificate_t*
	 */
	linked_list_t *certs;

	/**
	 * User name (ID)
	 */
	identification_t *user;

	/**
	 * User password
	 */
	char *pass;

	/**
	 * read/write lock
	 */
	rwlock_t *lock;

};

/**
 * Certificate enumerator data
 */
typedef struct {
	private_android_creds_t *this;
	key_type_t key;
	identification_t *id;
} cert_data_t;

/**
 * Filter function for certificates enumerator
 */
static bool cert_filter(cert_data_t *data, certificate_t **in,
						certificate_t **out)
{
	certificate_t *cert = *in;
	public_key_t *public;

	public = cert->get_public_key(cert);
	if (!public)
	{
		return FALSE;
	}
	if (data->key != KEY_ANY && public->get_type(public) != data->key)
	{
		public->destroy(public);
		return FALSE;
	}
	if (data->id && data->id->get_type(data->id) == ID_KEY_ID &&
		public->has_fingerprint(public, data->id->get_encoding(data->id)))
	{
		public->destroy(public);
		*out = cert;
		return TRUE;
	}
	public->destroy(public);
	if (data->id && !cert->has_subject(cert, data->id))
	{
		return FALSE;
	}
	*out = cert;
	return TRUE;
}

/**
 * Destroy certificate enumerator data
 */
static void cert_data_destroy(cert_data_t *this)
{
	this->this->lock->unlock(this->this->lock);
	free(this);
}

METHOD(credential_set_t, create_cert_enumerator, enumerator_t*,
	   private_android_creds_t *this, certificate_type_t cert, key_type_t key,
	   identification_t *id, bool trusted)
{
	if (cert == CERT_X509 || cert == CERT_ANY)
	{
		cert_data_t *data;
		this->lock->read_lock(this->lock);
		INIT(data, .this = this, .id = id, .key = key);
		return enumerator_create_filter(
						this->certs->create_enumerator(this->certs),
						(void*)cert_filter, data, (void*)cert_data_destroy);
	}
	return NULL;
}

/**
 * Shared key enumerator implementation
 */
typedef struct {
	enumerator_t public;
	private_android_creds_t *this;
	shared_key_t *key;
	bool done;
} shared_enumerator_t;

METHOD(enumerator_t, shared_enumerate, bool,
	   shared_enumerator_t *this, shared_key_t **key, id_match_t *me,
	   id_match_t *other)
{
	if (this->done)
	{
		return FALSE;
	}
	*key = this->key;
	*me = ID_MATCH_PERFECT;
	*other = ID_MATCH_ANY;
	this->done = TRUE;
	return TRUE;
}

METHOD(enumerator_t, shared_destroy, void,
	   shared_enumerator_t *this)
{
	this->key->destroy(this->key);
	this->this->lock->unlock(this->this->lock);
	free(this);
}

METHOD(credential_set_t, create_shared_enumerator, enumerator_t*,
	   private_android_creds_t *this, shared_key_type_t type,
	   identification_t *me, identification_t *other)
{
	shared_enumerator_t *enumerator;

	this->lock->read_lock(this->lock);

	if (!this->user || !this->pass)
	{
		this->lock->unlock(this->lock);
		return NULL;
	}
	if (type != SHARED_EAP && type != SHARED_IKE)
	{
		this->lock->unlock(this->lock);
		return NULL;
	}
	if (me && !me->equals(me, this->user))
	{
		this->lock->unlock(this->lock);
		return NULL;
	}

	INIT(enumerator,
		.public = {
			.enumerate = (void*)_shared_enumerate,
			.destroy = _shared_destroy,
		},
		.this = this,
		.done = FALSE,
		.key = shared_key_create(type, chunk_clone(chunk_create(this->pass,
												   strlen(this->pass)))),
	);
	return &enumerator->public;
}

METHOD(android_creds_t, add_certificate, bool,
	   private_android_creds_t *this, char *name)
{
	certificate_t *cert = NULL;
	bool status = FALSE;
	chunk_t chunk;
#ifdef KEYSTORE_MESSAGE_SIZE
	/* most current interface, the eclair interface (without key length) is
	 * currently not supported */
	char value[KEYSTORE_MESSAGE_SIZE];
	chunk.ptr = value;
	chunk.len = keystore_get(name, strlen(name), chunk.ptr);
	if (chunk.len > 0)
#else
	/* 1.6 interface, allocates memory */
	chunk.ptr = keystore_get(name, &chunk.len);
	if (chunk.ptr)
#endif /* KEYSTORE_MESSAGE_SIZE */
	{
		cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
								  BUILD_BLOB_PEM, chunk, BUILD_END);
		if (cert)
		{
			this->lock->write_lock(this->lock);
			this->certs->insert_last(this->certs, cert);
			this->lock->unlock(this->lock);
			status = TRUE;
		}
#ifndef KEYSTORE_MESSAGE_SIZE
		free(chunk.ptr);
#endif /* KEYSTORE_MESSAGE_SIZE */
	}
	return status;
}

METHOD(android_creds_t, set_username_password, void,
	   private_android_creds_t *this, identification_t *id, char *password)
{
	this->lock->write_lock(this->lock);
	DESTROY_IF(this->user);
	this->user = id->clone(id);
	free(this->pass);
	this->pass = strdupnull(password);
	this->lock->unlock(this->lock);
}

METHOD(android_creds_t, clear, void,
	   private_android_creds_t *this)
{
	certificate_t *cert;
	this->lock->write_lock(this->lock);
	while (this->certs->remove_last(this->certs, (void**)&cert) == SUCCESS)
	{
		cert->destroy(cert);
	}
	DESTROY_IF(this->user);
	free(this->pass);
	this->user = NULL;
	this->pass = NULL;
	this->lock->unlock(this->lock);
}

METHOD(android_creds_t, destroy, void,
	   private_android_creds_t *this)
{
	clear(this);
	this->certs->destroy(this->certs);
	this->lock->destroy(this->lock);
	free(this);
}

/**
 * Described in header.
 */
android_creds_t *android_creds_create()
{
	private_android_creds_t *this;

	INIT(this,
		.public = {
			.set = {
				.create_cert_enumerator = _create_cert_enumerator,
				.create_shared_enumerator = _create_shared_enumerator,
				.create_private_enumerator = (void*)return_null,
				.create_cdp_enumerator = (void*)return_null,
				.cache_cert = (void*)nop,
			},
			.add_certificate = _add_certificate,
			.set_username_password = _set_username_password,
			.clear = _clear,
			.destroy = _destroy,
		},
		.certs = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}

