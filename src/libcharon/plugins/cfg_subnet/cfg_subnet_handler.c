/*
 * Copyright (C) 2026 Manuel Montesdeoca
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

#include "cfg_subnet_handler.h"

#include <daemon.h>
#include <threading/mutex.h>
#include <collections/linked_list.h>

typedef struct private_cfg_subnet_handler_t private_cfg_subnet_handler_t;

/**
 * Private data of a cfg_subnet_handler_t object.
 */
struct private_cfg_subnet_handler_t {

	/**
	 * Public cfg_subnet_handler_t interface.
	 */
	cfg_subnet_handler_t public;

	/**
	 * Subnets received from the server, as entry_t
	 */
	linked_list_t *include;

	/**
	 * Mutex for concurrent access to the list
	 */
	mutex_t *mutex;
};

/**
 * Traffic selector entry for a subnet received under a given IKE_SA
 */
typedef struct {
	/** associated IKE_SA COOKIEs */
	ike_sa_id_t *id;
	/** traffic selector for the received subnet */
	traffic_selector_t *ts;
} entry_t;

/**
 * Clean up an entry
 */
static void entry_destroy(entry_t *this)
{
	this->id->destroy(this->id);
	this->ts->destroy(this->ts);
	free(this);
}

/**
 * Create a traffic selector for a received INTERNAL_IP4/6_SUBNET value
 */
static traffic_selector_t *create_ts(configuration_attribute_type_t type,
									 chunk_t data)
{
	switch (type)
	{
		case INTERNAL_IP4_SUBNET:
		{
			chunk_t net, mask;
			int i;

			if (data.len != 8)
			{
				return NULL;
			}
			net = chunk_create(data.ptr, 4);
			mask = chunk_clonea(chunk_create(data.ptr + 4, 4));
			for (i = 0; i < net.len; i++)
			{	/* normalize host bits in the mask to the top of the range */
				mask.ptr[i] = (mask.ptr[i] ^ 0xFF) | net.ptr[i];
			}
			return traffic_selector_create_from_bytes(0, TS_IPV4_ADDR_RANGE,
													  net, 0, mask, 65535);
		}
		case INTERNAL_IP6_SUBNET:
		{
			host_t *net;

			if (data.len != 17)
			{
				return NULL;
			}
			net = host_create_from_chunk(AF_INET6, chunk_create(data.ptr, 16),
										 0);
			if (!net)
			{
				return NULL;
			}
			return traffic_selector_create_from_subnet(net, data.ptr[16],
													   0, 0, 65535);
		}
		default:
			return NULL;
	}
}

/**
 * Store a subnet received for this IKE_SA
 */
static void add_subnet(private_cfg_subnet_handler_t *this, ike_sa_t *ike_sa,
					   traffic_selector_t *ts)
{
	ike_sa_id_t *id;
	entry_t *entry;

	id = ike_sa->get_id(ike_sa);
	INIT(entry,
		.id = id->clone(id),
		.ts = ts->clone(ts),
	);
	this->mutex->lock(this->mutex);
	this->include->insert_last(this->include, entry);
	this->mutex->unlock(this->mutex);
}

METHOD(attribute_handler_t, handle, bool,
	private_cfg_subnet_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	traffic_selector_t *ts;

	if (!ike_sa || ike_sa->get_version(ike_sa) != IKEV2)
	{
		return FALSE;
	}
	switch (type)
	{
		case INTERNAL_IP4_SUBNET:
		case INTERNAL_IP6_SUBNET:
			ts = create_ts(type, data);
			break;
		default:
			return FALSE;
	}
	if (!ts)
	{
		return FALSE;
	}
	DBG1(DBG_CFG, "received split tunnel subnet %R from server", ts);
	add_subnet(this, ike_sa, ts);
	ts->destroy(ts);
	return TRUE;
}

METHOD(attribute_handler_t, release, void,
	private_cfg_subnet_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{	/* invoked for each stored attribute, so later calls are no-ops */
	this->public.remove_includes(&this->public, ike_sa->get_id(ike_sa));
}

/**
 * Attribute enumerator implementation
 */
typedef struct {
	/** implements enumerator_t */
	enumerator_t public;
	/** attributes to request */
	configuration_attribute_type_t types[2];
	/** number of attributes to request */
	int count;
	/** position in types[] */
	int i;
} attribute_enumerator_t;

METHOD(enumerator_t, enumerate_attributes, bool,
	attribute_enumerator_t *this, va_list args)
{
	configuration_attribute_type_t *type;
	chunk_t *data;

	VA_ARGS_VGET(args, type, data);
	if (this->i < this->count)
	{
		*type = this->types[this->i++];
		*data = chunk_empty;
		return TRUE;
	}
	return FALSE;
}

METHOD(attribute_handler_t, create_attribute_enumerator, enumerator_t *,
	private_cfg_subnet_handler_t *this, ike_sa_t *ike_sa, linked_list_t *vips)
{
	attribute_enumerator_t *enumerator;
	enumerator_t *inner;
	host_t *vip;
	bool has_v4 = FALSE, has_v6 = FALSE;

	if (!ike_sa || ike_sa->get_version(ike_sa) != IKEV2 ||
		vips->get_count(vips) == 0)
	{
		return enumerator_create_empty();
	}
	/* only request the subnet attributes matching the virtual IP families we
	 * are going to request; a split list is useless without such an address */
	inner = vips->create_enumerator(vips);
	while (inner->enumerate(inner, &vip))
	{
		if (vip->get_family(vip) == AF_INET)
		{
			has_v4 = TRUE;
		}
		else
		{
			has_v6 = TRUE;
		}
	}
	inner->destroy(inner);
	INIT(enumerator,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _enumerate_attributes,
			.destroy = (void*)free,
		},
	);
	if (has_v4)
	{
		enumerator->types[enumerator->count++] = INTERNAL_IP4_SUBNET;
	}
	if (has_v6)
	{
		enumerator->types[enumerator->count++] = INTERNAL_IP6_SUBNET;
	}
	return &enumerator->public;
}

typedef struct {
	/** mutex to unlock */
	mutex_t *mutex;
	/** IKE_SA ID to filter for */
	ike_sa_id_t *id;
} include_filter_t;

CALLBACK(include_filter, bool,
	include_filter_t *data, enumerator_t *orig, va_list args)
{
	entry_t *entry;
	traffic_selector_t **ts;

	VA_ARGS_VGET(args, ts);

	while (orig->enumerate(orig, &entry))
	{
		if (data->id->equals(data->id, entry->id))
		{
			*ts = entry->ts;
			return TRUE;
		}
	}
	return FALSE;
}

CALLBACK(destroy_filter, void,
	include_filter_t *data)
{
	data->mutex->unlock(data->mutex);
	free(data);
}

METHOD(cfg_subnet_handler_t, create_include_enumerator, enumerator_t*,
	private_cfg_subnet_handler_t *this, ike_sa_id_t *id)
{
	include_filter_t *data;

	INIT(data,
		.mutex = this->mutex,
		.id = id,
	);
	data->mutex->lock(data->mutex);
	return enumerator_create_filter(
					this->include->create_enumerator(this->include),
					include_filter, data, destroy_filter);
}

METHOD(cfg_subnet_handler_t, migrate_includes, void,
	private_cfg_subnet_handler_t *this, ike_sa_id_t *old, ike_sa_id_t *new)
{
	enumerator_t *enumerator;
	entry_t *entry;

	this->mutex->lock(this->mutex);
	enumerator = this->include->create_enumerator(this->include);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->id->equals(entry->id, old))
		{
			entry->id->destroy(entry->id);
			entry->id = new->clone(new);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(cfg_subnet_handler_t, remove_includes, void,
	private_cfg_subnet_handler_t *this, ike_sa_id_t *id)
{
	enumerator_t *enumerator;
	entry_t *entry;

	this->mutex->lock(this->mutex);
	enumerator = this->include->create_enumerator(this->include);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->id->equals(entry->id, id))
		{
			this->include->remove_at(this->include, enumerator);
			entry_destroy(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(cfg_subnet_handler_t, destroy, void,
	private_cfg_subnet_handler_t *this)
{
	entry_t *entry;

	while (this->include->remove_first(this->include, (void**)&entry) == SUCCESS)
	{
		entry_destroy(entry);
	}
	this->include->destroy(this->include);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * see header file
 */
cfg_subnet_handler_t *cfg_subnet_handler_create()
{
	private_cfg_subnet_handler_t *this;

	INIT(this,
		.public = {
			.handler = {
				.handle = _handle,
				.release = _release,
				.create_attribute_enumerator = _create_attribute_enumerator,
			},
			.create_include_enumerator = _create_include_enumerator,
			.migrate_includes = _migrate_includes,
			.remove_includes = _remove_includes,
			.destroy = _destroy,
		},
		.include = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	return &this->public;
}
