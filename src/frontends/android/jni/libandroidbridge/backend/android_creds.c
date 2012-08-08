/*
 * Copyright (C) 2012 Tobias Brunner
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

#include "android_creds.h"
#include "../charonservice.h"

#include <daemon.h>
#include <library.h>
#include <credentials/sets/mem_cred.h>
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
	 * Credential set storing trusted certificates
	 */
	mem_cred_t *creds;

	/**
	 * read/write lock to make sure certificates are only loaded once
	 */
	rwlock_t *lock;

	/**
	 * TRUE if certificates have been loaded via JNI
	 */
	bool loaded;
};

/**
 * Load trusted certificates via charonservice (JNI).
 */
static void load_trusted_certificates(private_android_creds_t *this)
{
	linked_list_t *certs;
	certificate_t *cert;
	chunk_t *current;

	certs = charonservice->get_trusted_certificates(charonservice);
	if (certs)
	{
		while (certs->remove_first(certs, (void**)&current) == SUCCESS)
		{
			cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
									  BUILD_BLOB_ASN1_DER, *current, BUILD_END);
			if (cert)
			{
				DBG2(DBG_CFG, "loaded CA certificate '%Y'",
					 cert->get_subject(cert));
				this->creds->add_cert(this->creds, TRUE, cert);
			}
			chunk_free(current);
			free(current);
		}
		certs->destroy(certs);
	}
}

METHOD(credential_set_t, create_cert_enumerator, enumerator_t*,
	private_android_creds_t *this, certificate_type_t cert, key_type_t key,
	identification_t *id, bool trusted)
{
	enumerator_t *enumerator;

	if (!trusted || (cert != CERT_ANY && cert != CERT_X509))
	{
		return NULL;
	}
	this->lock->read_lock(this->lock);
	if (!this->loaded)
	{
		this->lock->unlock(this->lock);
		this->lock->write_lock(this->lock);
		/* check again after acquiring the write lock */
		if (!this->loaded)
		{
			load_trusted_certificates(this);
			this->loaded = TRUE;
		}
		this->lock->unlock(this->lock);
		this->lock->read_lock(this->lock);
	}
	enumerator = this->creds->set.create_cert_enumerator(&this->creds->set,
													cert, key, id, trusted);
	return enumerator_create_cleaner(enumerator, (void*)this->lock->unlock,
									 this->lock);
}

METHOD(android_creds_t, clear, void,
	private_android_creds_t *this)
{
	this->lock->write_lock(this->lock);
	this->creds->clear(this->creds);
	this->loaded = FALSE;
	this->lock->unlock(this->lock);
}

METHOD(android_creds_t, destroy, void,
	private_android_creds_t *this)
{
	clear(this);
	this->creds->destroy(this->creds);
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
				.create_shared_enumerator = (void*)return_null,
				.create_private_enumerator = (void*)return_null,
				.create_cdp_enumerator = (void*)return_null,
				.cache_cert = (void*)nop,
			},
			.clear = _clear,
			.destroy = _destroy,
		},
		.creds = mem_cred_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}
