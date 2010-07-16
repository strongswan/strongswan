/*
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
	 * List of shared keys, as shared_entry_t
	 */
	linked_list_t *shared;
};

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

METHOD(mem_cred_t, add_shared, void,
	private_mem_cred_t *this, shared_key_t *shared, ...)
{
	shared_entry_t *entry;
	identification_t *id;
	va_list args;

	INIT(entry,
		.shared = shared,
		.owners = linked_list_create(),
	);

	va_start(args, shared);
	do
	{
		id = va_arg(args, identification_t*);
		if (id)
		{
			entry->owners->insert_last(entry->owners, id);
		}
	}
	while (id);
	va_end(args);

	this->lock->write_lock(this->lock);
	this->shared->insert_last(this->shared, entry);
	this->lock->unlock(this->lock);
}


METHOD(mem_cred_t, destroy, void,
	private_mem_cred_t *this)
{
	this->shared->destroy_function(this->shared, (void*)shared_entry_destroy);
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
				.create_private_enumerator = (void*)return_null,
				.create_cert_enumerator = (void*)return_null,
				.create_cdp_enumerator  = (void*)return_null,
				.cache_cert = (void*)nop,
			},
			.add_shared = _add_shared,
			.destroy = _destroy,
		},
		.shared = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	return &this->public;
}
