/*
 * Copyright (C) 2011 Martin Willi
 * Copyright (C) 2011 revosec AG
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

#include "certexpire_export.h"

#include <debug.h>
#include <utils/hashtable.h>
#include <threading/mutex.h>
#include <credentials/certificates/x509.h>

typedef struct private_certexpire_export_t private_certexpire_export_t;

/**
 * Private data of an certexpire_export_t object.
 */
struct private_certexpire_export_t {

	/**
	 * Public certexpire_export_t interface.
	 */
	certexpire_export_t public;

	/**
	 * hashtable caching local trustchains, mapping entry_t => entry_t
	 */
	hashtable_t *local;

	/**
	 * hashtable caching remote trustchains, mapping entry_t => entry_t
	 */
	hashtable_t *remote;

	/**
	 * Mutex to lock hashtables
	 */
	mutex_t *mutex;
};

/**
 * Maximum number of expiration dates we store (for subject + IM CAs + CA)
 */
#define MAX_TRUSTCHAIN_LENGTH 7

/**
 * Hashtable entry
 */
typedef struct {
	/** certificate subject as subjectAltName or CN of a DN */
	char id[128];
	/** list of expiration dates, 0 if no certificate */
	time_t expire[MAX_TRUSTCHAIN_LENGTH];
} entry_t;

/**
 * Hashtable hash function
 */
static u_int hash(entry_t *key)
{
	return chunk_hash(chunk_create(key->id, strlen(key->id)));
}

/**
 * Hashtable equals function
 */
static bool equals(entry_t *a, entry_t *b)
{
	return streq(a->id, b->id);
}

METHOD(certexpire_export_t, add, void,
	private_certexpire_export_t *this, linked_list_t *trustchain, bool local)
{
	enumerator_t *enumerator;
	certificate_t *cert;
	int count;

	count = min(trustchain->get_count(trustchain), MAX_TRUSTCHAIN_LENGTH) - 1;

	enumerator = trustchain->create_enumerator(trustchain);
	/* get subject cert */
	if (enumerator->enumerate(enumerator, &cert))
	{
		identification_t *id;
		entry_t *entry;
		int i;

		INIT(entry);

		/* prefer FQDN subjectAltName... */
		if (cert->get_type(cert) == CERT_X509)
		{
			x509_t *x509 = (x509_t*)cert;
			enumerator_t *sans;

			sans = x509->create_subjectAltName_enumerator(x509);
			while (sans->enumerate(sans, &id))
			{
				if (id->get_type(id) == ID_FQDN)
				{
					snprintf(entry->id, sizeof(entry->id), "%Y", id);
					break;
				}
			}
			sans->destroy(sans);
		}
		/* fallback to CN of DN */
		if (!entry->id[0])
		{
			enumerator_t *parts;
			id_part_t part;
			chunk_t data;

			id = cert->get_subject(cert);
			parts = id->create_part_enumerator(id);
			while (parts->enumerate(parts, &part, &data))
			{
				if (part == ID_PART_RDN_CN)
				{
					snprintf(entry->id, sizeof(entry->id), "%.*s",
							 (int)data.len, data.ptr);
					break;
				}
			}
			parts->destroy(parts);
		}
		/* no usable identity? skip */
		if (!entry->id[0])
		{
			enumerator->destroy(enumerator);
			free(entry);
			return;
		}

		/* get intermediate CA expiration dates */
		cert->get_validity(cert, NULL, NULL, &entry->expire[0]);
		for (i = 1; i < count && enumerator->enumerate(enumerator, &cert); i++)
		{
			cert->get_validity(cert, NULL, NULL, &entry->expire[i]);
		}
		/* get CA expiration date, as last array entry */
		if (enumerator->enumerate(enumerator, &cert))
		{
			cert->get_validity(cert, NULL, NULL,
							   &entry->expire[MAX_TRUSTCHAIN_LENGTH - 1]);
		}
		this->mutex->lock(this->mutex);
		if (local)
		{
			entry = this->local->put(this->local, entry, entry);
		}
		else
		{
			entry = this->remote->put(this->remote, entry, entry);
		}
		this->mutex->unlock(this->mutex);
		if (entry)
		{
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
}

METHOD(certexpire_export_t, destroy, void,
	private_certexpire_export_t *this)
{
	entry_t *key, *value;
	enumerator_t *enumerator;

	enumerator = this->local->create_enumerator(this->local);
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		free(value);
	}
	enumerator->destroy(enumerator);
	enumerator = this->remote->create_enumerator(this->remote);
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		free(value);
	}
	enumerator->destroy(enumerator);

	this->local->destroy(this->local);
	this->remote->destroy(this->remote);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
certexpire_export_t *certexpire_export_create()
{
	private_certexpire_export_t *this;

	INIT(this,
		.public = {
			.add = _add,
			.destroy = _destroy,
		},
		.local = hashtable_create((hashtable_hash_t)hash,
								  (hashtable_equals_t)equals, 4),
		.remote = hashtable_create((hashtable_hash_t)hash,
								   (hashtable_equals_t)equals, 32),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	return &this->public;
}
