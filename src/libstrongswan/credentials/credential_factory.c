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
	 * mutex to lock access to modules
	 */
	mutex_t *mutex;
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
 * Implementation of credential_factory_t.create_builder.
 */
static builder_t* create_builder(private_credential_factory_t *this,
								 credential_type_t type, int subtype)
{
	enumerator_t *enumerator;
	entry_t *entry;
	builder_t *builder = NULL;
	
	this->mutex->lock(this->mutex);
	enumerator = this->constructors->create_enumerator(this->constructors);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->type == type && entry->subtype == subtype)
		{
			builder = entry->constructor(subtype);
			if (builder)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	return builder;
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
	this->mutex->lock(this->mutex);
	this->constructors->insert_last(this->constructors, entry);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of credential_factory_t.remove_builder.
 */
static void remove_builder(private_credential_factory_t *this,
						   builder_constructor_t constructor)
{
	enumerator_t *enumerator;
	entry_t *entry;
	
	this->mutex->lock(this->mutex);
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
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of credential_factory_t.create.
 */
static void* create(private_credential_factory_t *this, credential_type_t type,
					int subtype, ...)
{
	builder_t *builder;
	builder_part_t part;
	va_list args;
	
	builder = create_builder(this, type, subtype);
	if (builder)
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
				case BUILD_FROM_FILE:
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
					builder->add(builder, part, va_arg(args, void*));
					continue;
				default:
					DBG1("builder part %N not supported by factory",
						 builder_part_names, part);
					break;
			}
			break;
		}
		va_end(args);
	
		return builder->build(builder);
	}
	else
	{
		DBG1("failed to create a builder for credential type %N,"
				" subtype (%d)", credential_type_names, type, subtype);
	}
	
	/** shredder all data on failure */
	va_start(args, subtype);
	while (TRUE)
	{
		part = va_arg(args, builder_part_t);
		
		switch (part)
		{
			case BUILD_END:
				break;
			case BUILD_BLOB_ASN1_DER:
			{
				chunk_t chunk = va_arg(args, chunk_t);
				free(chunk.ptr);
				continue;
			}
			case BUILD_SERIAL:
			{
				va_arg(args, chunk_t);
				continue;
			}
			case BUILD_X509_FLAG:
			{
				va_arg(args, x509_flag_t);
				continue;
			}
			case BUILD_KEY_SIZE:
			{
				va_arg(args, u_int);
				continue;
			}
			case BUILD_NOT_BEFORE_TIME:
			case BUILD_NOT_AFTER_TIME:
			{
				va_arg(args, time_t);
				continue;
			}
			case BUILD_SIGNING_KEY:
			{
				private_key_t *private = va_arg(args, private_key_t*);
				private->destroy(private);
				continue;
			}
			case BUILD_PUBLIC_KEY:
			{
				public_key_t *public = va_arg(args, public_key_t*);
				public->destroy(public);
				continue;
			}
			case BUILD_SUBJECT:
			case BUILD_SUBJECT_ALTNAME:
			case BUILD_ISSUER:
			case BUILD_ISSUER_ALTNAME:
			{
				identification_t *id = va_arg(args, identification_t*);
				id->destroy(id);
				continue;
			}
			case BUILD_SIGNING_CERT:
			case BUILD_CA_CERT:
			case BUILD_CERT:
			{
				certificate_t *cert = va_arg(args, certificate_t*);
				cert->destroy(cert);
				continue;
			}
			case BUILD_FROM_FILE:
			case BUILD_IETF_GROUP_ATTR:
			{
				va_arg(args, void*);
				continue;
			}
			default:
				DBG1("builder part %N not supported by factory",
					 builder_part_names, part);
				continue;
		}
		break;
	}
	va_end(args);
	return NULL;
}

/**
 * Implementation of credential_factory_t.destroy
 */
static void destroy(private_credential_factory_t *this)
{
	this->constructors->destroy_function(this->constructors, free);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * see header file
 */
credential_factory_t *credential_factory_create()
{
	private_credential_factory_t *this = malloc_thing(private_credential_factory_t);

	this->public.create = (void*(*)(credential_factory_t*, credential_type_t type, int subtype, ...))create;
	this->public.create_builder = (builder_t*(*)(credential_factory_t*, credential_type_t type, int subtype))create_builder;
	this->public.add_builder = (void(*)(credential_factory_t*,credential_type_t type, int subtype, builder_constructor_t constructor))add_builder;
	this->public.remove_builder = (void(*)(credential_factory_t*,builder_constructor_t constructor))remove_builder;
	this->public.destroy = (void(*)(credential_factory_t*))destroy;
	
	this->constructors = linked_list_create();
	
	this->mutex = mutex_create(MUTEX_RECURSIVE);
	
	return &this->public;
}

