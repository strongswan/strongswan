/*
 * Copyright (C) 2010 Tobias Brunner
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

#include <hydra.h>
#include <debug.h>
#include <utils/linked_list.h>

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
static enumerator_t* create_attribute_enumerator(private_attr_provider_t *this,
											identification_t *id, host_t *vip)
{
	if (vip)
	{
		return enumerator_create_filter(
						this->attributes->create_enumerator(this->attributes),
						(void*)attr_enum_filter, NULL, NULL);
	}
	return enumerator_create_empty();
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
static void add_legacy_entry(private_attr_provider_t *this, char *key, int nr,
							 configuration_attribute_type_t type)
{
	attribute_entry_t *entry;
	host_t *host;
	char *str;

	str = lib->settings->get_str(lib->settings, "%s.%s%d", NULL, hydra->daemon,
								 key, nr);
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

/**
 * Key to attribute type mappings, for v4 and v6 attributes
 */
static struct {
	char *name;
	configuration_attribute_type_t v4;
	configuration_attribute_type_t v6;
} keys[] = {
	{"address",		INTERNAL_IP4_ADDRESS,	INTERNAL_IP6_ADDRESS},
	{"dns",			INTERNAL_IP4_DNS,		INTERNAL_IP6_DNS},
	{"nbns",		INTERNAL_IP4_NBNS,		INTERNAL_IP6_NBNS},
	{"dhcp",		INTERNAL_IP4_DHCP,		INTERNAL_IP6_DHCP},
	{"netmask",		INTERNAL_IP4_NETMASK,	INTERNAL_IP6_NETMASK},
	{"server",		INTERNAL_IP4_SERVER,	INTERNAL_IP6_SERVER},
};

/**
 * Load (numerical) entries from the plugins.attr namespace
 */
static void load_entries(private_attr_provider_t *this)
{
	enumerator_t *enumerator, *tokens;
	char *key, *value, *token;

	enumerator = lib->settings->create_key_value_enumerator(lib->settings,
											"%s.plugins.attr", hydra->daemon);
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		configuration_attribute_type_t type;
		attribute_entry_t *entry;
		host_t *host;
		int i;

		type = atoi(key);
		tokens = enumerator_create_token(value, ",", " ");
		while (tokens->enumerate(tokens, &token))
		{
			host = host_create_from_string(token, 0);
			if (!host)
			{
				DBG1("invalid host in key %s: %s", key, token);
				continue;
			}
			if (!type)
			{
				for (i = 0; i < countof(keys); i++)
				{
					if (streq(key, keys[i].name))
					{
						if (host->get_family(host) == AF_INET)
						{
							type = keys[i].v4;
						}
						else
						{
							type = keys[i].v6;
						}
					}
				}
				if (!type)
				{
					DBG1("mapping attribute type %s failed", key);
					break;
				}
			}
			entry = malloc_thing(attribute_entry_t);
			entry->type = type;
			entry->value = chunk_clone(host->get_address(host));
			host->destroy(host);
			this->attributes->insert_last(this->attributes, entry);
		}
		tokens->destroy(tokens);
	}
	enumerator->destroy(enumerator);
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
	this->public.provider.create_attribute_enumerator = (enumerator_t*(*)(attribute_provider_t*, identification_t *id, host_t *vip))create_attribute_enumerator;
	this->public.destroy = (void(*)(attr_provider_t*))destroy;

	this->attributes = linked_list_create();

	for (i = 1; i <= SERVER_MAX; i++)
	{
		add_legacy_entry(this, "dns", i, INTERNAL_IP4_DNS);
		add_legacy_entry(this, "nbns", i, INTERNAL_IP4_NBNS);
	}

	load_entries(this);

	return &this->public;
}

