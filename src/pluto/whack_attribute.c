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

#include "whack_attribute.h"

#include "log.h"

/* these are defined as constants in constant.h but redefined as enum values in
 * attributes/attributes.h */
#undef INTERNAL_IP4_SERVER
#undef INTERNAL_IP6_SERVER

#include <hydra.h>
#include <attributes/mem_pool.h>
#include <utils/linked_list.h>
#include <threading/rwlock.h>

typedef struct private_whack_attribute_t private_whack_attribute_t;

/**
 * private data of whack_attribute
 */
struct private_whack_attribute_t {

	/**
	 * public functions
	 */
	whack_attribute_t public;

	/**
	 * list of pools, contains mem_pool_t
	 */
	linked_list_t *pools;

	/**
	 * rwlock to lock access to pools
	 */
	rwlock_t *lock;
};

/**
 * global object
 */
whack_attribute_t *whack_attr;

/**
 * compare pools by name
 */
static bool pool_match(mem_pool_t *current, char *name)
{
	return name && streq(name, current->get_name(current));
}

/**
 * find a pool by name
 */
static mem_pool_t *find_pool(private_whack_attribute_t *this, char *name)
{
	mem_pool_t *found;
	if (this->pools->find_first(this->pools, (linked_list_match_t)pool_match,
		(void**)&found, name) == SUCCESS)
	{
		return found;
	}
	return NULL;
}

METHOD(attribute_provider_t, acquire_address, host_t*,
	   private_whack_attribute_t *this, char *name, identification_t *id,
	   host_t *requested)
{
	mem_pool_t *pool;
	host_t *addr = NULL;
	this->lock->read_lock(this->lock);
	pool = find_pool(this, name);
	if (pool)
	{
		addr = pool->acquire_address(pool, id, requested);
	}
	this->lock->unlock(this->lock);
	return addr;
}

METHOD(attribute_provider_t, release_address, bool,
	   private_whack_attribute_t *this, char *name, host_t *address,
	   identification_t *id)
{
	mem_pool_t *pool;
	bool found = FALSE;
	this->lock->read_lock(this->lock);
	pool = find_pool(this, name);
	if (pool)
	{
		found = pool->release_address(pool, address, id);
	}
	this->lock->unlock(this->lock);
	return found;
}

METHOD(whack_attribute_t, add_pool, bool,
	   private_whack_attribute_t *this, const char *name,
	   const whack_end_t *right)
{
	mem_pool_t *pool;
	host_t *base = NULL;
	u_int32_t bits = 0;

	/* named pool */
	if (right->sourceip_mask <= 0)
	{
		return FALSE;
	}

	/* if %config, add an empty pool, otherwise */
	if (right->sourceip)
	{
		DBG(DBG_CONTROL,
			DBG_log("adding virtual IP address pool '%s': %s/%d",
					name, right->sourceip, right->sourceip_mask);
		);
		base = host_create_from_string(right->sourceip, 0);
		if (!base)
		{
			loglog(RC_LOG_SERIOUS, "virtual IP address invalid, discarded");
			return FALSE;
		}
		bits = right->sourceip_mask;
	}
	pool = mem_pool_create((char*)name, base, bits);
	DESTROY_IF(base);

	this->lock->write_lock(this->lock);
	this->pools->insert_last(this->pools, pool);
	this->lock->unlock(this->lock);
	return TRUE;
}

METHOD(whack_attribute_t, del_pool, void,
	   private_whack_attribute_t *this, char *name)
{
	enumerator_t *enumerator;
	mem_pool_t *pool;

	this->lock->write_lock(this->lock);
	enumerator = this->pools->create_enumerator(this->pools);
	while (enumerator->enumerate(enumerator, &pool))
	{
		if (streq(name, pool->get_name(pool)))
		{
			DBG(DBG_CONTROL,
				DBG_log("deleting virtual IP address pool '%s'", name)
			);
			this->pools->remove_at(this->pools, enumerator);
			pool->destroy(pool);
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

/**
 * Pool enumerator filter function, converts pool_t to name, size, ...
 */
static bool pool_filter(void *lock, mem_pool_t **poolp, const char **name,
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

METHOD(whack_attribute_t, create_pool_enumerator, enumerator_t*,
	   private_whack_attribute_t *this)
{
	this->lock->read_lock(this->lock);
	return enumerator_create_filter(this->pools->create_enumerator(this->pools),
									(void*)pool_filter,
									this->lock, (void*)this->lock->unlock);
}

METHOD(whack_attribute_t, create_lease_enumerator, enumerator_t*,
	   private_whack_attribute_t *this, char *name)
{
	mem_pool_t *pool;
	this->lock->read_lock(this->lock);
	pool = find_pool(this, name);
	if (!pool)
	{
		this->lock->unlock(this->lock);
		return NULL;
	}
	return enumerator_create_cleaner(pool->create_lease_enumerator(pool),
									 (void*)this->lock->unlock, this->lock);
}

/**
 * see header file
 */
void whack_attribute_finalize()
{
	private_whack_attribute_t *this = (private_whack_attribute_t*)whack_attr;
	hydra->attributes->remove_provider(hydra->attributes,
									   &this->public.provider);
	this->lock->destroy(this->lock);
	this->pools->destroy_offset(this->pools, offsetof(mem_pool_t, destroy));
	free(this);
}

/**
 * see header file
 */
void whack_attribute_initialize()
{
	private_whack_attribute_t *this;

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
		},
		.pools = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	hydra->attributes->add_provider(hydra->attributes, &this->public.provider);

	whack_attr = &this->public;
}

/**
 * list leases of a single pool
 */
static void pool_leases(char *pool, host_t *address,
						identification_t *identification,
						u_int size, u_int online, u_int offline)
{

	enumerator_t *enumerator;
	identification_t *id;
	host_t *lease;
	bool on, found = FALSE;

	whack_log(RC_COMMENT, "Leases in pool '%s', usage: %lu/%lu, %lu online",
			  pool, online + offline, size, online);
	enumerator = whack_attr->create_lease_enumerator(whack_attr, pool);
	while (enumerator && enumerator->enumerate(enumerator, &id, &lease, &on))
	{
		if ((!address && !identification) ||
			(address && address->ip_equals(address, lease)) ||
			(identification && identification->equals(identification, id)))
		{
			whack_log(RC_COMMENT, "  %15H   %s   '%Y'",
					  lease, on ? "online" : "offline", id);
			found = TRUE;
		}
	}
	enumerator->destroy(enumerator);
	if (!found)
	{
		whack_log(RC_COMMENT, "  no matching leases found");
	}
}

/**
 * see header file
 */
void list_leases(char *name, char *addr, char *id)
{
	identification_t *identification = NULL;
	host_t *address = NULL;
	bool found = FALSE;
	enumerator_t *enumerator;
	u_int size, online, offline;
	char *pool;

	if (addr)
	{
		address = host_create_from_string(addr, 0);
	}
	if (id)
	{
		identification = identification_create_from_string(id);
	}

	enumerator = whack_attr->create_pool_enumerator(whack_attr);
	while (enumerator->enumerate(enumerator, &pool, &size, &online, &offline))
	{
		if (!name || streq(name, pool))
		{
			pool_leases(pool, address, identification, size, online, offline);
			found = TRUE;
		}
	}
	enumerator->destroy(enumerator);
	if (!found)
	{
		if (name)
		{
			whack_log(RC_COMMENT, "pool '%s' not found", name);
		}
		else
		{
			whack_log(RC_COMMENT, "no pools found");
		}
	}
	DESTROY_IF(identification);
	DESTROY_IF(address);
}

