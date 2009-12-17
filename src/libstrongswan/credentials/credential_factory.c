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

#include <stdint.h>

#include "credential_factory.h"

#include <debug.h>
#include <utils/linked_list.h>
#include <threading/thread_value.h>
#include <threading/rwlock.h>
#include <credentials/certificates/x509.h>

ENUM(credential_type_names, CRED_PRIVATE_KEY, CRED_CERTIFICATE,
	"CRED_PRIVATE_KEY",
	"CRED_PUBLIC_KEY",
	"CRED_CERTIFICATE",
	"CRED_PLUTO_CERT",
);

typedef struct private_credential_factory_t private_credential_factory_t;

/**
 * private data of credential_factory
 */
struct private_credential_factory_t {

	/**
	 * public functions
	 */
	credential_factory_t public;

	/**
	 * list with entry_t
	 */
	linked_list_t *constructors;

	/**
	 * Thread specific recursiveness counter
	 */
	thread_value_t *recursive;

	/**
	 * lock access to builders
	 */
	rwlock_t *lock;
};

typedef struct entry_t entry_t;
struct entry_t {
	/** kind of credential builder */
	credential_type_t type;
	/** subtype of credential, e.g. certificate_type_t */
	int subtype;
	/** builder function */
	builder_function_t constructor;
};

/**
 * Implementation of credential_factory_t.add_builder_constructor.
 */
static void add_builder(private_credential_factory_t *this,
						credential_type_t type, int subtype,
						builder_function_t constructor)
{
	entry_t *entry = malloc_thing(entry_t);

	entry->type = type;
	entry->subtype = subtype;
	entry->constructor = constructor;
	this->lock->write_lock(this->lock);
	this->constructors->insert_last(this->constructors, entry);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of credential_factory_t.remove_builder.
 */
static void remove_builder(private_credential_factory_t *this,
						   builder_function_t constructor)
{
	enumerator_t *enumerator;
	entry_t *entry;

	this->lock->write_lock(this->lock);
	enumerator = this->constructors->create_enumerator(this->constructors);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->constructor == constructor)
		{
			this->constructors->remove_at(this->constructors, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of credential_factory_t.create.
 */
static void* create(private_credential_factory_t *this, credential_type_t type,
					int subtype, ...)
{
	enumerator_t *enumerator;
	entry_t *entry;
	va_list args;
	void *construct = NULL;
	int failures = 0;
	uintptr_t level;

	level = (uintptr_t)this->recursive->get(this->recursive);
	this->recursive->set(this->recursive, (void*)level + 1);

	this->lock->read_lock(this->lock);
	enumerator = this->constructors->create_enumerator(this->constructors);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->type == type && entry->subtype == subtype)
		{
			va_start(args, subtype);
			construct = entry->constructor(subtype, args);
			va_end(args);
			if (construct)
			{
				break;
			}
			failures++;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	if (!construct && !level)
	{
		enum_name_t *names = key_type_names;

		if (type == CRED_CERTIFICATE)
		{
			names = certificate_type_names;
		}
		DBG1("building %N - %N failed, tried %d builders",
			 credential_type_names, type, names, subtype, failures);
	}
	this->recursive->set(this->recursive, (void*)level);
	return construct;
}

/**
 * Implementation of credential_factory_t.destroy
 */
static void destroy(private_credential_factory_t *this)
{
	this->constructors->destroy_function(this->constructors, free);
	this->recursive->destroy(this->recursive);
	this->lock->destroy(this->lock);
	free(this);
}

/*
 * see header file
 */
credential_factory_t *credential_factory_create()
{
	private_credential_factory_t *this = malloc_thing(private_credential_factory_t);

	this->public.create = (void*(*)(credential_factory_t*, credential_type_t type, int subtype, ...))create;
	this->public.add_builder = (void(*)(credential_factory_t*,credential_type_t type, int subtype, builder_function_t constructor))add_builder;
	this->public.remove_builder = (void(*)(credential_factory_t*,builder_function_t constructor))remove_builder;
	this->public.destroy = (void(*)(credential_factory_t*))destroy;

	this->constructors = linked_list_create();
	this->recursive = thread_value_create(NULL);
	this->lock = rwlock_create(RWLOCK_TYPE_DEFAULT);

	return &this->public;
}

