/*
 * Copyright (C) 2010 Tobias Brunner
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

#include "stroke_attribute.h"

#include <daemon.h>
#include <attributes/mem_pool.h>
#include <utils/linked_list.h>
#include <threading/mutex.h>

typedef struct private_stroke_attribute_t private_stroke_attribute_t;

/**
 * private data of stroke_attribute
 */
struct private_stroke_attribute_t {

	/**
	 * public functions
	 */
	stroke_attribute_t public;

	/**
	 * list of pools, contains mem_pool_t
	 */
	linked_list_t *pools;

	/**
	 * mutex to lock access to pools
	 */
	mutex_t *mutex;
};

/**
 * find a pool by name
 */
static mem_pool_t *find_pool(private_stroke_attribute_t *this, char *name)
{
	enumerator_t *enumerator;
	mem_pool_t *current, *found = NULL;

	enumerator = this->pools->create_enumerator(this->pools);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (streq(name, current->get_name(current)))
		{
			found = current;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

METHOD(attribute_provider_t, acquire_address, host_t*,
	   private_stroke_attribute_t *this, char *name, identification_t *id,
	   host_t *requested)
{
	mem_pool_t *pool;
	host_t *addr = NULL;
	this->mutex->lock(this->mutex);
	pool = find_pool(this, name);
	if (pool)
	{
		addr = pool->acquire_address(pool, id, requested);
	}
	this->mutex->unlock(this->mutex);
	return addr;
}

METHOD(attribute_provider_t, release_address, bool,
	   private_stroke_attribute_t *this, char *name, host_t *address,
	   identification_t *id)
{
	mem_pool_t *pool;
	bool found = FALSE;
	this->mutex->lock(this->mutex);
	pool = find_pool(this, name);
	if (pool)
	{
		found = pool->release_address(pool, address, id);
	}
	this->mutex->unlock(this->mutex);
	return found;
}

METHOD(stroke_attribute_t, add_pool, void,
	   private_stroke_attribute_t *this, stroke_msg_t *msg)
{
	if (msg->add_conn.other.sourceip_mask)
	{
		mem_pool_t *pool;
		host_t *base = NULL;
		u_int32_t bits = 0;

		/* if %config, add an empty pool, otherwise */
		if (msg->add_conn.other.sourceip)
		{
			DBG1(DBG_CFG, "adding virtual IP address pool '%s': %s/%d",
				 msg->add_conn.name, msg->add_conn.other.sourceip,
				 msg->add_conn.other.sourceip_mask);
			base = host_create_from_string(msg->add_conn.other.sourceip, 0);
			if (!base)
			{
				DBG1(DBG_CFG, "virtual IP address invalid, discarded");
				return;
			}
			bits = msg->add_conn.other.sourceip_mask;
		}
		pool = mem_pool_create(msg->add_conn.name, base, bits);
		DESTROY_IF(base);

		this->mutex->lock(this->mutex);
		this->pools->insert_last(this->pools, pool);
		this->mutex->unlock(this->mutex);
	}
}

METHOD(stroke_attribute_t, del_pool, void,
	   private_stroke_attribute_t *this, stroke_msg_t *msg)
{
	enumerator_t *enumerator;
	mem_pool_t *pool;

	this->mutex->lock(this->mutex);
	enumerator = this->pools->create_enumerator(this->pools);
	while (enumerator->enumerate(enumerator, &pool))
	{
		if (streq(msg->del_conn.name, pool->get_name(pool)))
		{
			this->pools->remove_at(this->pools, enumerator);
			pool->destroy(pool);
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

/**
 * Pool enumerator filter function, converts pool_t to name, size, ...
 */
static bool pool_filter(void *mutex, mem_pool_t **poolp, const char **name,
						void *d1, u_int *size, void *d2, u_int *online,
						void *d3, u_int *offline)
{
	mem_pool_t *pool = *poolp;
	*name = pool->get_name(pool);
	*size = pool->get_size(pool);
	*online = pool->get_online(pool);
	*offline = pool->get_offline(pool);
	return TRUE;
}

METHOD(stroke_attribute_t, create_pool_enumerator, enumerator_t*,
	   private_stroke_attribute_t *this)
{
	this->mutex->lock(this->mutex);
	return enumerator_create_filter(this->pools->create_enumerator(this->pools),
									(void*)pool_filter,
									this->mutex, (void*)this->mutex->unlock);
}

METHOD(stroke_attribute_t, create_lease_enumerator, enumerator_t*,
	   private_stroke_attribute_t *this, char *name)
{
	mem_pool_t *pool;
	this->mutex->lock(this->mutex);
	pool = find_pool(this, name);
	if (!pool)
	{
		this->mutex->unlock(this->mutex);
		return NULL;
	}
	return enumerator_create_cleaner(pool->create_lease_enumerator(pool),
									 (void*)this->mutex->unlock, this->mutex);
}

METHOD(stroke_attribute_t, destroy, void,
	   private_stroke_attribute_t *this)
{
	this->mutex->destroy(this->mutex);
	this->pools->destroy_offset(this->pools, offsetof(mem_pool_t, destroy));
	free(this);
}

/*
 * see header file
 */
stroke_attribute_t *stroke_attribute_create()
{
	private_stroke_attribute_t *this;

	INIT(this,
		.public = {
			.provider = {
				.acquire_address = _acquire_address,
				.release_address = _release_address,
				.create_attribute_enumerator = enumerator_create_empty,
			},
			.add_pool = _add_pool,
			.del_pool = _del_pool,
			.create_pool_enumerator = _create_pool_enumerator,
			.create_lease_enumerator = _create_lease_enumerator,
			.destroy = _destroy,
		},
		.pools = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
	);

	return &this->public;
}

