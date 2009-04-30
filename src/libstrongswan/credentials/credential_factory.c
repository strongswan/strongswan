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

#include "credential_factory.h"

#include <debug.h>
#include <utils/linked_list.h>
#include <utils/mutex.h>
#include <credentials/certificates/x509.h>

ENUM(credential_type_names, CRED_PRIVATE_KEY, CRED_CERTIFICATE,
	"CRED_PRIVATE_KEY",
	"CRED_PUBLIC_KEY",
	"CRED_CERTIFICATE",
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
	/** builder construction function */
	builder_constructor_t constructor;
};

/**
 * type/subtype filter function for builder_enumerator
 */
static bool builder_filter(entry_t *data, entry_t **in, builder_t **out)
{
	if (data->type == (*in)->type &&
		data->subtype == (*in)->subtype)
	{
		*out = (*in)->constructor(data->subtype);
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of credential_factory_t.create_builder_enumerator.
 */
static enumerator_t* create_builder_enumerator(
		private_credential_factory_t *this,	credential_type_t type, int subtype)
{
	entry_t *data = malloc_thing(entry_t);
	
	data->type = type;
	data->subtype = subtype;
	
	this->lock->read_lock(this->lock);
	return enumerator_create_cleaner(
				enumerator_create_filter(
					this->constructors->create_enumerator(this->constructors),
					(void*)builder_filter, data, free), 
				(void*)this->lock->unlock, this->lock);
}

/**
 * Implementation of credential_factory_t.add_builder_constructor.
 */
static void add_builder(private_credential_factory_t *this,
						credential_type_t type, int subtype,
						builder_constructor_t constructor)
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
						   builder_constructor_t constructor)
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
	builder_t *builder;
	builder_part_t part;
	va_list args;
	void* construct = NULL;
	
	enumerator = create_builder_enumerator(this, type, subtype);
	while (enumerator->enumerate(enumerator, &builder))
	{
		va_start(args, subtype);
		while (TRUE)
		{
			part = va_arg(args, builder_part_t);
			switch (part)
			{
				case BUILD_END:
					break;
				case BUILD_BLOB_ASN1_DER:
				case BUILD_SERIAL:
					builder->add(builder, part, va_arg(args, chunk_t));
					continue;
				case BUILD_X509_FLAG:
					builder->add(builder, part, va_arg(args, x509_flag_t));
					continue;
				case BUILD_KEY_SIZE:
					builder->add(builder, part, va_arg(args, u_int));
					continue;
				case BUILD_NOT_BEFORE_TIME:
				case BUILD_NOT_AFTER_TIME:
					builder->add(builder, part, va_arg(args, time_t));
					continue;
				case BUILD_BLOB_ASN1_PEM:
				case BUILD_FROM_FILE:
				case BUILD_AGENT_SOCKET:
				case BUILD_SIGNING_KEY:
				case BUILD_PUBLIC_KEY:
				case BUILD_SUBJECT:
				case BUILD_SUBJECT_ALTNAME:
				case BUILD_ISSUER:
				case BUILD_ISSUER_ALTNAME:
				case BUILD_SIGNING_CERT:
				case BUILD_CA_CERT:
				case BUILD_CERT:
				case BUILD_IETF_GROUP_ATTR:
				case BUILD_SMARTCARD_KEYID:
				case BUILD_SMARTCARD_PIN:
					builder->add(builder, part, va_arg(args, void*));
					continue;
				/* no default to get a compiler warning */
			}
			break;
		}
		va_end(args);
		
		construct = builder->build(builder);
		if (construct)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (!construct)
	{
		DBG1("failed to create a builder for credential type %N,"
			 " subtype (%d)", credential_type_names, type, subtype);
	}
	return construct;
}

/**
 * Implementation of credential_factory_t.destroy
 */
static void destroy(private_credential_factory_t *this)
{
	this->constructors->destroy_function(this->constructors, free);
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
	this->public.create_builder_enumerator = (enumerator_t*(*)(credential_factory_t*, credential_type_t type, int subtype))create_builder_enumerator;
	this->public.add_builder = (void(*)(credential_factory_t*,credential_type_t type, int subtype, builder_constructor_t constructor))add_builder;
	this->public.remove_builder = (void(*)(credential_factory_t*,builder_constructor_t constructor))remove_builder;
	this->public.destroy = (void(*)(credential_factory_t*))destroy;
	
	this->constructors = linked_list_create();
	
	this->lock = rwlock_create(RWLOCK_DEFAULT);
	
	return &this->public;
}

