/*
 * Copyright (C) 2009 Martin Willi
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

#include "attr_provider.h"

#include <time.h>

#include <daemon.h>

#define SERVER_MAX		2

typedef struct private_attr_provider_t private_attr_provider_t;
typedef struct attribute_entry_t attribute_entry_t;

/**
 * private data of attr_provider
 */
struct private_attr_provider_t {
	
	/**
	 * public functions
	 */
	attr_provider_t public;
	
	/**
	 * List of attributes, attribute_entry_t
	 */
	linked_list_t *attributes;
};

struct attribute_entry_t {
	/** type of attribute */
	configuration_attribute_type_t type;
	/** attribute value */
	chunk_t value;
};

/**
 * convert enumerator value from attribute_entry
 */
static bool attr_enum_filter(void *null, attribute_entry_t **in,
			configuration_attribute_type_t *type, void* none, chunk_t *value)
{
	*type = (*in)->type;
	*value = (*in)->value;
	return TRUE;
}

/**
 * Implementation of attribute_provider_t.create_attribute_enumerator
 */
static enumerator_t* create_attribute_enumerator(
					private_attr_provider_t *this, identification_t *id)
{
	return enumerator_create_filter(
						this->attributes->create_enumerator(this->attributes),
						(void*)attr_enum_filter, NULL, NULL);
}

/**
 * Implementation of attr_provider_t.destroy
 */
static void destroy(private_attr_provider_t *this)
{
	attribute_entry_t *entry;
	
	while (this->attributes->remove_last(this->attributes,
										 (void**)&entry) == SUCCESS)
	{
		free(entry->value.ptr);
		free(entry);
	}
	this->attributes->destroy(this->attributes);
	free(this);
}

/**
 * Add an attribute entry to the list
 */
static void add_entry(private_attr_provider_t *this, char *key, int nr,
					  configuration_attribute_type_t type)
{
	attribute_entry_t *entry;
	host_t *host;
	char *str;
	
	str = lib->settings->get_str(lib->settings, "charon.%s%d", NULL, key, nr);
	if (str)
	{
		host = host_create_from_string(str, 0);
		if (host)
		{
			entry = malloc_thing(attribute_entry_t);
			
			if (host->get_family(host) == AF_INET6)
			{
				switch (type)
				{
					case INTERNAL_IP4_DNS:
						type = INTERNAL_IP6_DNS;
						break;
					case INTERNAL_IP4_NBNS:
						type = INTERNAL_IP6_NBNS;
						break;
					default:
						break;
				}
			}
			entry->type = type;
			entry->value = chunk_clone(host->get_address(host));
			host->destroy(host);
			this->attributes->insert_last(this->attributes, entry);
		}
	}
}

/*
 * see header file
 */
attr_provider_t *attr_provider_create(database_t *db)
{
	private_attr_provider_t *this;
	int i;
	
	this = malloc_thing(private_attr_provider_t);
	
	this->public.provider.acquire_address = (host_t*(*)(attribute_provider_t *this, char*, identification_t *, host_t *))return_null;
	this->public.provider.release_address = (bool(*)(attribute_provider_t *this, char*,host_t *, identification_t*))return_false;
	this->public.provider.create_attribute_enumerator = (enumerator_t*(*)(attribute_provider_t*, identification_t *id))create_attribute_enumerator;
	this->public.destroy = (void(*)(attr_provider_t*))destroy;
	
	this->attributes = linked_list_create();
	
	for (i = 1; i <= SERVER_MAX; i++)
	{
		add_entry(this, "dns", i, INTERNAL_IP4_DNS);
		add_entry(this, "nbns", i, INTERNAL_IP4_NBNS);
	}
	
	return &this->public;
}

