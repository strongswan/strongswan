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
 */

#include "nm_creds.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <daemon.h>
#include <utils/mutex.h>
#include <credentials/certificates/x509.h>

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
	 * List of trusted certificates, certificate_t*
	 */
	linked_list_t *certs;

	/**
	 * User name
	 */
	identification_t *user;

	/**
	 * User password
	 */
	char *pass;

	/**
	 * users certificate
	 */
	certificate_t *usercert;

	/**
	 * users private key
	 */
	private_key_t *key;

	/**
	 * read/write lock
	 */
	rwlock_t *lock;
};

/**
 * Enumerator for user certificate
 */
static enumerator_t *create_usercert_enumerator(private_nm_creds_t *this,
							certificate_type_t cert, key_type_t key)
{
	public_key_t *public;

	if (cert != CERT_ANY && cert != this->usercert->get_type(this->usercert))
	{
		return NULL;
	}
	if (key != KEY_ANY)
	{
		public = this->usercert->get_public_key(this->usercert);
		if (!public)
		{
			return NULL;
		}
		if (public->get_type(public) != key)
		{
			public->destroy(public);
			return NULL;
		}
		public->destroy(public);
	}
	this->lock->read_lock(this->lock);
	return enumerator_create_cleaner(
								enumerator_create_single(this->usercert, NULL),
								(void*)this->lock->unlock, this->lock);
}

/**
 * CA certificate enumerator data
 */
typedef struct {
	/** ref to credential credential store */
	private_nm_creds_t *this;
	/** type of key we are looking for */
	key_type_t key;
	/** CA certificate ID */
	identification_t *id;
} cert_data_t;

/**
 * Destroy CA certificate enumerator data
 */
static void cert_data_destroy(cert_data_t *data)
{
	data->this->lock->unlock(data->this->lock);
	free(data);
}

/**
 * Filter function for certificates enumerator
 */
static bool cert_filter(cert_data_t *data, certificate_t **in,
						 certificate_t **out)
{
	certificate_t *cert = *in;
	public_key_t *public;
	chunk_t keyid;

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
		public->get_fingerprint(public, KEY_ID_PUBKEY_SHA1, &keyid) &&
		chunk_equals(keyid, data->id->get_encoding(data->id)))
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
 * Create enumerator for trusted certificates
 */
static enumerator_t *create_trusted_cert_enumerator(private_nm_creds_t *this,
										key_type_t key, identification_t *id)
{
	cert_data_t *data = malloc_thing(cert_data_t);

	data->this = this;
	data->id = id;
	data->key = key;

	this->lock->read_lock(this->lock);
	return enumerator_create_filter(
					this->certs->create_enumerator(this->certs),
					(void*)cert_filter, data, (void*)cert_data_destroy);
}

/**
 * Implements credential_set_t.create_cert_enumerator
 */
static enumerator_t* create_cert_enumerator(private_nm_creds_t *this,
							certificate_type_t cert, key_type_t key,
							identification_t *id, bool trusted)
{
	if (id && this->usercert &&
		id->equals(id, this->usercert->get_subject(this->usercert)))
	{
		return create_usercert_enumerator(this, cert, key);
	}
	if (cert == CERT_X509 || cert == CERT_ANY)
	{
		return create_trusted_cert_enumerator(this, key, id);
	}
	return NULL;
}

/**
 * Implements credential_set_t.create_cert_enumerator
 */
static enumerator_t* create_private_enumerator(private_nm_creds_t *this,
										key_type_t type, identification_t *id)
{
	if (this->key == NULL)
	{
		return NULL;
	}
	if (type != KEY_ANY && type != this->key->get_type(this->key))
	{
		return NULL;
	}
	if (id && id->get_type(id) != ID_ANY)
	{
		chunk_t keyid;

		if (id->get_type(id) != ID_KEY_ID ||
			!this->key->get_fingerprint(this->key, KEY_ID_PUBKEY_SHA1, &keyid) ||
			!chunk_equals(keyid, id->get_encoding(id)))
		{
			return NULL;
		}
	}
	this->lock->read_lock(this->lock);
	return enumerator_create_cleaner(enumerator_create_single(this->key, NULL),
									 (void*)this->lock->unlock, this->lock);
}

/**
 * shared key enumerator implementation
 */
typedef struct {
	enumerator_t public;
	private_nm_creds_t *this;
	shared_key_t *key;
	bool done;
} shared_enumerator_t;

/**
 * enumerate function for shared enumerator
 */
static bool shared_enumerate(shared_enumerator_t *this, shared_key_t **key,
							 id_match_t *me, id_match_t *other)
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

/**
 * Destroy function for shared enumerator
 */
static void shared_destroy(shared_enumerator_t *this)
{
	this->key->destroy(this->key);
	this->this->lock->unlock(this->this->lock);
	free(this);
}
/**
 * Implements credential_set_t.create_cert_enumerator
 */
static enumerator_t* create_shared_enumerator(private_nm_creds_t *this,
							shared_key_type_t type,	identification_t *me,
							identification_t *other)
{
	shared_enumerator_t *enumerator;

	if (!this->pass || !this->user)
	{
		return NULL;
	}
	if (type != SHARED_EAP && type != SHARED_IKE)
	{
		return NULL;
	}
	if (me && !me->equals(me, this->user))
	{
		return NULL;
	}

	enumerator = malloc_thing(shared_enumerator_t);
	enumerator->public.enumerate = (void*)shared_enumerate;
	enumerator->public.destroy = (void*)shared_destroy;
	enumerator->this = this;
	enumerator->done = FALSE;
	this->lock->read_lock(this->lock);
	enumerator->key = shared_key_create(type,
										chunk_clone(chunk_create(this->pass,
													strlen(this->pass))));
	return &enumerator->public;
}

/**
 * Implementation of nm_creds_t.add_certificate
 */
static void add_certificate(private_nm_creds_t *this, certificate_t *cert)
{
	this->lock->write_lock(this->lock);
	this->certs->insert_last(this->certs, cert);
	this->lock->unlock(this->lock);
}

/**
 * Load a certificate file
 */
static void load_ca_file(private_nm_creds_t *this, char *file)
{
	certificate_t *cert;

	/* We add the CA constraint, as many CAs miss it */
	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
							  BUILD_FROM_FILE, file, BUILD_END);
	if (!cert)
	{
		DBG1(DBG_CFG, "loading CA certificate '%s' failed", file);
	}
	else
	{
		DBG2(DBG_CFG, "loaded CA certificate '%Y'", cert->get_subject(cert));
		x509_t *x509 = (x509_t*)cert;
		if (!(x509->get_flags(x509) & X509_SELF_SIGNED))
		{
			DBG1(DBG_CFG, "%Y is not self signed", cert->get_subject(cert));
		}
		this->certs->insert_last(this->certs, cert);
	}
}

/**
 * Implementation of nm_creds_t.load_ca_dir
 */
static void load_ca_dir(private_nm_creds_t *this, char *dir)
{
	enumerator_t *enumerator;
	char *rel, *abs;
	struct stat st;

	enumerator = enumerator_create_directory(dir);
	if (enumerator)
	{
		while (enumerator->enumerate(enumerator, &rel, &abs, &st))
		{
			/* skip '.', '..' and hidden files */
			if (rel[0] != '.')
			{
				if (S_ISDIR(st.st_mode))
				{
					load_ca_dir(this, abs);
				}
				else if (S_ISREG(st.st_mode))
				{
					load_ca_file(this, abs);
				}
			}
		}
		enumerator->destroy(enumerator);
	}
}

/**
 * Implementation of nm_creds_t.set_password
 */
static void set_username_password(private_nm_creds_t *this, identification_t *id,
						 char *password)
{
	this->lock->write_lock(this->lock);
	DESTROY_IF(this->user);
	this->user = id->clone(id);
	free(this->pass);
	this->pass = password ? strdup(password) : NULL;
	this->lock->unlock(this->lock);
}

/**
 * Implementation of nm_creds_t.set_cert_and_key
 */
static void set_cert_and_key(private_nm_creds_t *this, certificate_t *cert,
							 private_key_t *key)
{
	this->lock->write_lock(this->lock);
	DESTROY_IF(this->key);
	DESTROY_IF(this->usercert);
	this->key = key;
	this->usercert = cert;
	this->lock->unlock(this->lock);
}

/**
 * Implementation of nm_creds_t.clear
 */
static void clear(private_nm_creds_t *this)
{
	certificate_t *cert;

	while (this->certs->remove_last(this->certs, (void**)&cert) == SUCCESS)
	{
		cert->destroy(cert);
	}
	DESTROY_IF(this->user);
	free(this->pass);
	DESTROY_IF(this->usercert);
	DESTROY_IF(this->key);
	this->key = NULL;
	this->usercert = NULL;
	this->pass = NULL;
	this->user = NULL;
}

/**
 * Implementation of nm_creds_t.destroy
 */
static void destroy(private_nm_creds_t *this)
{
	clear(this);
	this->certs->destroy(this->certs);
	this->lock->destroy(this->lock);
	free(this);
}

/*
 * see header file
 */
nm_creds_t *nm_creds_create()
{
	private_nm_creds_t *this = malloc_thing(private_nm_creds_t);

	this->public.set.create_private_enumerator = (void*)create_private_enumerator;
	this->public.set.create_cert_enumerator = (void*)create_cert_enumerator;
	this->public.set.create_shared_enumerator = (void*)create_shared_enumerator;
	this->public.set.create_cdp_enumerator = (void*)return_null;
	this->public.set.cache_cert = (void*)nop;
	this->public.add_certificate = (void(*)(nm_creds_t*, certificate_t *cert))add_certificate;
	this->public.load_ca_dir = (void(*)(nm_creds_t*, char *dir))load_ca_dir;
	this->public.set_username_password = (void(*)(nm_creds_t*, identification_t *id, char *password))set_username_password;
	this->public.set_cert_and_key = (void(*)(nm_creds_t*, certificate_t *cert, private_key_t *key))set_cert_and_key;
	this->public.clear = (void(*)(nm_creds_t*))clear;
	this->public.destroy = (void(*)(nm_creds_t*))destroy;

	this->lock = rwlock_create(RWLOCK_TYPE_DEFAULT);

	this->certs = linked_list_create();
	this->user = NULL;
	this->pass = NULL;
	this->usercert = NULL;
	this->key = NULL;

	return &this->public;
}

