/*
 * Copyright (C) 2010 Tobias Brunner
 * Hochschule fuer Technik Rapperwsil
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "mem_cred.h"

#include <threading/rwlock.h>
#include <utils/linked_list.h>

typedef struct private_mem_cred_t private_mem_cred_t;

/**
 * Private data of an mem_cred_t object.
 */
struct private_mem_cred_t {

	/**
	 * Public mem_cred_t interface.
	 */
	mem_cred_t public;

	/**
	 * Lock for this set
	 */
	rwlock_t *lock;

	/**
	 * List of trusted certificates, certificate_t
	 */
	linked_list_t *trusted;

	/**
	 * List of trusted and untrusted certificates, certificate_t
	 */
	linked_list_t *untrusted;

	/**
	 * List of private keys, private_key_t
	 */
	linked_list_t *keys;

	/**
	 * List of shared keys, as shared_entry_t
	 */
	linked_list_t *shared;
};

/**
 * Data for the certificate enumerator
 */
typedef struct {
	rwlock_t *lock;
	certificate_type_t cert;
	key_type_t key;
	identification_t *id;
} cert_data_t;

/**
 * destroy cert_data
 */
static void cert_data_destroy(cert_data_t *data)
{
	data->lock->unlock(data->lock);
	free(data);
}

/**
 * filter function for certs enumerator
 */
static bool certs_filter(cert_data_t *data, certificate_t **in, certificate_t **out)
{
	public_key_t *public;
	certificate_t *cert = *in;

	if (data->cert == CERT_ANY || data->cert == cert->get_type(cert))
	{
		public = cert->get_public_key(cert);
		if (public)
		{
			if (data->key == KEY_ANY || data->key == public->get_type(public))
			{
				if (data->id && public->has_fingerprint(public,
											data->id->get_encoding(data->id)))
				{
					public->destroy(public);
					*out = *in;
					return TRUE;
				}
			}
			public->destroy(public);
		}
		else if (data->key != KEY_ANY)
		{
			return FALSE;
		}
		if (data->id == NULL || cert->has_subject(cert, data->id))
		{
			*out = *in;
			return TRUE;
		}
	}
	return FALSE;
}

METHOD(credential_set_t, create_cert_enumerator, enumerator_t*,
	private_mem_cred_t *this, certificate_type_t cert, key_type_t key,
	identification_t *id, bool trusted)
{
	cert_data_t *data;
	enumerator_t *enumerator;

	INIT(data,
		.lock = this->lock,
		.cert = cert,
		.key = key,
		.id = id,
	);
	this->lock->read_lock(this->lock);
	if (trusted)
	{
		enumerator = this->trusted->create_enumerator(this->trusted);
	}
	else
	{
		enumerator = this->untrusted->create_enumerator(this->untrusted);
	}
	return enumerator_create_filter(enumerator, (void*)certs_filter, data,
									(void*)cert_data_destroy);
}

static bool certificate_equals(certificate_t *item, certificate_t *cert)
{
	return item->equals(item, cert);
}

/**
 * Add a certificate the the cache. Returns a reference to "cert" or a
 * previously cached certificate that equals "cert".
 */
static certificate_t *add_cert_internal(private_mem_cred_t *this, bool trusted,
										certificate_t *cert)
{
	certificate_t *cached;
	this->lock->write_lock(this->lock);
	if (this->untrusted->find_last(this->untrusted,
								   (linked_list_match_t)certificate_equals,
								   (void**)&cached, cert) == SUCCESS)
	{
		cert->destroy(cert);
		cert = cached->get_ref(cached);
	}
	else
	{
		if (trusted)
		{
			this->trusted->insert_last(this->trusted, cert->get_ref(cert));
		}
		this->untrusted->insert_last(this->untrusted, cert->get_ref(cert));
	}
	this->lock->unlock(this->lock);
	return cert;
}

METHOD(mem_cred_t, add_cert, void,
	private_mem_cred_t *this, bool trusted, certificate_t *cert)
{
	certificate_t *cached = add_cert_internal(this, trusted, cert);
	cached->destroy(cached);
}

METHOD(mem_cred_t, add_cert_ref, certificate_t*,
	private_mem_cred_t *this, bool trusted, certificate_t *cert)
{
	return add_cert_internal(this, trusted, cert);
}

/**
 * Data for key enumerator
 */
typedef struct {
	rwlock_t *lock;
	key_type_t type;
	identification_t *id;
} key_data_t;

/**
 * Destroy key enumerator data
 */
static void key_data_destroy(key_data_t *data)
{
	data->lock->unlock(data->lock);
	free(data);
}

/**
 * filter function for private key enumerator
 */
static bool key_filter(key_data_t *data, private_key_t **in, private_key_t **out)
{
	private_key_t *key;

	key = *in;
	if (data->type == KEY_ANY || data->type == key->get_type(key))
	{
		if (data->id == NULL ||
			key->has_fingerprint(key, data->id->get_encoding(data->id)))
		{
			*out = key;
			return TRUE;
		}
	}
	return FALSE;
}

METHOD(credential_set_t, create_private_enumerator, enumerator_t*,
	private_mem_cred_t *this, key_type_t type, identification_t *id)
{
	key_data_t *data;

	INIT(data,
		.lock = this->lock,
		.type = type,
		.id = id,
	);
	this->lock->read_lock(this->lock);
	return enumerator_create_filter(this->keys->create_enumerator(this->keys),
							(void*)key_filter, data, (void*)key_data_destroy);
}

METHOD(mem_cred_t, add_key, void,
	private_mem_cred_t *this, private_key_t *key)
{
	this->lock->write_lock(this->lock);
	this->keys->insert_last(this->keys, key);
	this->lock->unlock(this->lock);
}

/**
 * Shared key entry
 */
typedef struct {
	/* shared key */
	shared_key_t *shared;
	/* list of owners, identification_t */
	linked_list_t *owners;
} shared_entry_t;

/**
 * Clean up a shared entry
 */
static void shared_entry_destroy(shared_entry_t *entry)
{
	entry->owners->destroy_offset(entry->owners,
								  offsetof(identification_t, destroy));
	entry->shared->destroy(entry->shared);
	free(entry);
}

/**
 * Data for the shared_key enumerator
 */
typedef struct {
	rwlock_t *lock;
	identification_t *me;
	identification_t *other;
	shared_key_type_t type;
} shared_data_t;

/**
 * free shared key enumerator data and unlock list
 */
static void shared_data_destroy(shared_data_t *data)
{
	data->lock->unlock(data->lock);
	free(data);
}

/**
 * Get the best match of an owner in an entry.
 */
static id_match_t has_owner(shared_entry_t *entry, identification_t *owner)
{
	enumerator_t *enumerator;
	id_match_t match, best = ID_MATCH_NONE;
	identification_t *current;

	enumerator = entry->owners->create_enumerator(entry->owners);
	while (enumerator->enumerate(enumerator, &current))
	{
		match  = owner->matches(owner, current);
		if (match > best)
		{
			best = match;
		}
	}
	enumerator->destroy(enumerator);
	return best;
}

/**
 * enumerator filter function for shared entries
 */
static bool shared_filter(shared_data_t *data,
						  shared_entry_t **in, shared_key_t **out,
						  void **unused1, id_match_t *me,
						  void **unused2, id_match_t *other)
{
	id_match_t my_match = ID_MATCH_NONE, other_match = ID_MATCH_NONE;
	shared_entry_t *entry = *in;

	if (data->type != SHARED_ANY &&
		entry->shared->get_type(entry->shared) != data->type)
	{
		return FALSE;
	}
	if (data->me)
	{
		my_match = has_owner(entry, data->me);
	}
	if (data->other)
	{
		other_match = has_owner(entry, data->other);
	}
	if ((data->me || data->other) && (!my_match && !other_match))
	{
		return FALSE;
	}
	*out = entry->shared;
	if (me)
	{
		*me = my_match;
	}
	if (other)
	{
		*other = other_match;
	}
	return TRUE;
}

METHOD(credential_set_t, create_shared_enumerator, enumerator_t*,
	private_mem_cred_t *this, shared_key_type_t type,
	identification_t *me, identification_t *other)
{
	shared_data_t *data;

	INIT(data,
		.lock = this->lock,
		.me = me,
		.other = other,
		.type = type,
	);
	data->lock->read_lock(data->lock);
	return enumerator_create_filter(
						this->shared->create_enumerator(this->shared),
						(void*)shared_filter, data, (void*)shared_data_destroy);
}

METHOD(mem_cred_t, add_shared_list, void,
	private_mem_cred_t *this, shared_key_t *shared, linked_list_t* owners)
{
	shared_entry_t *entry;

	INIT(entry,
		.shared = shared,
		.owners = owners,
	);

	this->lock->write_lock(this->lock);
	this->shared->insert_last(this->shared, entry);
	this->lock->unlock(this->lock);
}

METHOD(mem_cred_t, add_shared, void,
	private_mem_cred_t *this, shared_key_t *shared, ...)
{
	identification_t *id;
	linked_list_t *owners = linked_list_create();
	va_list args;

	va_start(args, shared);
	do
	{
		id = va_arg(args, identification_t*);
		if (id)
		{
			owners->insert_last(owners, id);
		}
	}
	while (id);
	va_end(args);

	add_shared_list(this, shared, owners);
}

METHOD(mem_cred_t, clear_, void,
	private_mem_cred_t *this)
{
	this->lock->write_lock(this->lock);
	this->trusted->destroy_offset(this->trusted,
								  offsetof(certificate_t, destroy));
	this->untrusted->destroy_offset(this->untrusted,
									offsetof(certificate_t, destroy));
	this->keys->destroy_offset(this->keys, offsetof(private_key_t, destroy));
	this->shared->destroy_function(this->shared, (void*)shared_entry_destroy);
	this->trusted = linked_list_create();
	this->untrusted = linked_list_create();
	this->keys = linked_list_create();
	this->shared = linked_list_create();
	this->lock->unlock(this->lock);
}

METHOD(mem_cred_t, destroy, void,
	private_mem_cred_t *this)
{
	clear_(this);
	this->trusted->destroy(this->trusted);
	this->untrusted->destroy(this->untrusted);
	this->keys->destroy(this->keys);
	this->shared->destroy(this->shared);
	this->lock->destroy(this->lock);
	free(this);
}

/**
 * See header
 */
mem_cred_t *mem_cred_create()
{
	private_mem_cred_t *this;

	INIT(this,
		.public = {
			.set = {
				.create_shared_enumerator = _create_shared_enumerator,
				.create_private_enumerator = _create_private_enumerator,
				.create_cert_enumerator = _create_cert_enumerator,
				.create_cdp_enumerator  = (void*)return_null,
				.cache_cert = (void*)nop,
			},
			.add_cert = _add_cert,
			.add_cert_ref = _add_cert_ref,
			.add_key = _add_key,
			.add_shared = _add_shared,
			.add_shared_list = _add_shared_list,
			.clear = _clear_,
			.destroy = _destroy,
		},
		.trusted = linked_list_create(),
		.untrusted = linked_list_create(),
		.keys = linked_list_create(),
		.shared = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}
