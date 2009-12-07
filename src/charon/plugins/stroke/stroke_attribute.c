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

#include "stroke_attribute.h"

#include <daemon.h>
#include <utils/linked_list.h>
#include <utils/hashtable.h>
#include <threading.h>

#define POOL_LIMIT (sizeof(uintptr_t)*8)

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
	 * list of pools, contains pool_t
	 */
	linked_list_t *pools;

	/**
	 * mutex to lock access to pools
	 */
	mutex_t *mutex;
};

typedef struct {
	/** name of the pool */
	char *name;
	/** base address of the pool */
	host_t *base;
	/** size of the pool */
	int size;
	/** next unused address */
	int unused;
	/** hashtable [identity => offset], for online leases */
	hashtable_t *online;
	/** hashtable [identity => offset], for offline leases */
	hashtable_t *offline;
	/** hashtable [identity => identity], handles identity references */
	hashtable_t *ids;
} pool_t;

/**
 * hashtable hash function for identities
 */
static u_int id_hash(identification_t *id)
{
	return chunk_hash(id->get_encoding(id));
}

/**
 * hashtable equals function for identities
 */
static bool id_equals(identification_t *a, identification_t *b)
{
	return a->equals(a, b);
}

/**
 * destroy a pool_t
 */
static void pool_destroy(pool_t *this)
{
	enumerator_t *enumerator;
	identification_t *id;

	enumerator = this->ids->create_enumerator(this->ids);
	while (enumerator->enumerate(enumerator, &id, NULL))
	{
		id->destroy(id);
	}
	enumerator->destroy(enumerator);
	this->ids->destroy(this->ids);
	this->online->destroy(this->online);
	this->offline->destroy(this->offline);
	DESTROY_IF(this->base);
	free(this->name);
	free(this);
}

/**
 * find a pool by name
 */
static pool_t *find_pool(private_stroke_attribute_t *this, char *name)
{
	enumerator_t *enumerator;
	pool_t *current, *found = NULL;

	enumerator = this->pools->create_enumerator(this->pools);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (streq(name, current->name))
		{
			found = current;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * convert an pool offset to an address
 */
host_t* offset2host(pool_t *pool, int offset)
{
	chunk_t addr;
	host_t *host;
	u_int32_t *pos;

	offset--;
	if (offset > pool->size)
	{
		return NULL;
	}

	addr = chunk_clone(pool->base->get_address(pool->base));
	if (pool->base->get_family(pool->base) == AF_INET6)
	{
		pos = (u_int32_t*)(addr.ptr + 12);
	}
	else
	{
		pos = (u_int32_t*)addr.ptr;
	}
	*pos = htonl(offset + ntohl(*pos));
	host = host_create_from_chunk(pool->base->get_family(pool->base), addr, 0);
	free(addr.ptr);
	return host;
}

/**
 * convert a host to a pool offset
 */
int host2offset(pool_t *pool, host_t *addr)
{
	chunk_t host, base;
	u_int32_t hosti, basei;

	if (addr->get_family(addr) != pool->base->get_family(pool->base))
	{
		return -1;
	}
	host = addr->get_address(addr);
	base = pool->base->get_address(pool->base);
	if (addr->get_family(addr) == AF_INET6)
	{
		/* only look at last /32 block */
		if (!memeq(host.ptr, base.ptr, 12))
		{
			return -1;
		}
		host = chunk_skip(host, 12);
		base = chunk_skip(base, 12);
	}
	hosti = ntohl(*(u_int32_t*)(host.ptr));
	basei = ntohl(*(u_int32_t*)(base.ptr));
	if (hosti > basei + pool->size)
	{
		return -1;
	}
	return hosti - basei + 1;
}

/**
 * Implementation of attribute_provider_t.acquire_address
 */
static host_t* acquire_address(private_stroke_attribute_t *this,
							   char *name, identification_t *id,
							   host_t *requested)
{
	pool_t *pool;
	uintptr_t offset = 0;
	enumerator_t *enumerator;
	identification_t *old_id;

	this->mutex->lock(this->mutex);
	pool = find_pool(this, name);
	while (pool)
	{
		/* handle %config case by mirroring requested address */
		if (pool->size == 0)
		{
			this->mutex->unlock(this->mutex);
			return requested->clone(requested);
		}

		if (!requested->is_anyaddr(requested) &&
			requested->get_family(requested) !=
			pool->base->get_family(pool->base))
		{
			DBG1(DBG_CFG, "IP pool address family mismatch");
			break;
		}

		/* check for a valid offline lease, refresh */
		offset = (uintptr_t)pool->offline->remove(pool->offline, id);
		if (offset)
		{
			id = pool->ids->get(pool->ids, id);
			if (id)
			{
				DBG1(DBG_CFG, "reassigning offline lease to '%Y'", id);
				pool->online->put(pool->online, id, (void*)offset);
				break;
			}
		}

		/* check for a valid online lease, reassign */
		offset = (uintptr_t)pool->online->get(pool->online, id);
		if (offset && offset == host2offset(pool, requested))
		{
			DBG1(DBG_CFG, "reassigning online lease to '%Y'", id);
			break;
		}

		if (pool->unused < pool->size)
		{
			/* assigning offset, starting by 1. Handling 0 in hashtable
			 * is difficult. */
			offset = ++pool->unused;
			id = id->clone(id);
			pool->ids->put(pool->ids, id, id);
			pool->online->put(pool->online, id, (void*)offset);
			DBG1(DBG_CFG, "assigning new lease to '%Y'", id);
			break;
		}
		/* no more addresses, replace the first found offline lease */
		enumerator = pool->offline->create_enumerator(pool->offline);
		if (enumerator->enumerate(enumerator, &old_id, &offset))
		{
			offset = (uintptr_t)pool->offline->remove(pool->offline, old_id);
			if (offset)
			{
				/* destroy reference to old ID */
				old_id = pool->ids->remove(pool->ids, old_id);
				DBG1(DBG_CFG, "reassigning existing offline lease by '%Y' to '%Y'",
					 old_id, id);
				if (old_id)
				{
					old_id->destroy(old_id);
				}
				id = id->clone(id);
				pool->ids->put(pool->ids, id, id);
				pool->online->put(pool->online, id, (void*)offset);
				enumerator->destroy(enumerator);
				break;
			}
		}
		enumerator->destroy(enumerator);

		DBG1(DBG_CFG, "pool '%s' is full, unable to assign address", name);
		break;
	}
	this->mutex->unlock(this->mutex);
	if (offset)
	{
		return offset2host(pool, offset);
	}
	return NULL;
}

/**
 * Implementation of attribute_provider_t.release_address
 */
static bool release_address(private_stroke_attribute_t *this,
							char *name, host_t *address, identification_t *id)
{
	pool_t *pool;
	bool found = FALSE;
	uintptr_t offset;

	this->mutex->lock(this->mutex);
	pool = find_pool(this, name);
	if (pool)
	{
		if (pool->size != 0)
		{
			offset = (uintptr_t)pool->online->remove(pool->online, id);
			if (offset)
			{
				id = pool->ids->get(pool->ids, id);
				if (id)
				{
					DBG1(DBG_CFG, "lease %H by '%Y' went offline", address, id);
					pool->offline->put(pool->offline, id, (void*)offset);
					found = TRUE;
				}
			}
		}
	}
	this->mutex->unlock(this->mutex);
	return found;
}

/**
 * Implementation of stroke_attribute_t.add_pool.
 */
static void add_pool(private_stroke_attribute_t *this, stroke_msg_t *msg)
{
	if (msg->add_conn.other.sourceip_mask)
	{
		pool_t *pool;

		pool = malloc_thing(pool_t);
		pool->base = NULL;
		pool->size = 0;
		pool->unused = 0;
		pool->name = strdup(msg->add_conn.name);
		pool->online = hashtable_create((hashtable_hash_t)id_hash,
										(hashtable_equals_t)id_equals, 16);
		pool->offline = hashtable_create((hashtable_hash_t)id_hash,
										(hashtable_equals_t)id_equals, 16);
		pool->ids = hashtable_create((hashtable_hash_t)id_hash,
										(hashtable_equals_t)id_equals, 16);

		/* if %config, add an empty pool, otherwise */
		if (msg->add_conn.other.sourceip)
		{
			u_int32_t bits;
			int family;

			DBG1(DBG_CFG, "adding virtual IP address pool '%s': %s/%d",
				 msg->add_conn.name, msg->add_conn.other.sourceip,
				 msg->add_conn.other.sourceip_mask);

			pool->base = host_create_from_string(msg->add_conn.other.sourceip, 0);
			if (!pool->base)
			{
				pool_destroy(pool);
				DBG1(DBG_CFG, "virtual IP address invalid, discarded");
				return;
			}
			family = pool->base->get_family(pool->base);
			bits = (family == AF_INET ? 32 : 128) - msg->add_conn.other.sourceip_mask;
			if (bits > POOL_LIMIT)
			{
				bits = POOL_LIMIT;
				DBG1(DBG_CFG, "virtual IP pool to large, limiting to %s/%d",
					 msg->add_conn.other.sourceip,
					 (family == AF_INET ? 32 : 128) - bits);
			}
			pool->size = 1 << (bits);

			if (pool->size > 2)
			{	/* do not use first and last addresses of a block */
				pool->unused++;
				pool->size--;
			}
		}
		this->mutex->lock(this->mutex);
		this->pools->insert_last(this->pools, pool);
		this->mutex->unlock(this->mutex);
	}
}

/**
 * Implementation of stroke_attribute_t.del_pool.
 */
static void del_pool(private_stroke_attribute_t *this, stroke_msg_t *msg)
{
	enumerator_t *enumerator;
	pool_t *pool;

	this->mutex->lock(this->mutex);
	enumerator = this->pools->create_enumerator(this->pools);
	while (enumerator->enumerate(enumerator, &pool))
	{
		if (streq(msg->del_conn.name, pool->name))
		{
			this->pools->remove_at(this->pools, enumerator);
			pool_destroy(pool);
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

/**
 * Pool enumerator filter function, converts pool_t to name, size, ...
 */
static bool pool_filter(void *mutex, pool_t **poolp, char **name,
						void *d1, u_int *size, void *d2, u_int *online,
						void *d3, u_int *offline)
{
	pool_t *pool = *poolp;

	*name = pool->name;
	*size = pool->size;
	*online = pool->online->get_count(pool->online);
	*offline = pool->offline->get_count(pool->offline);
	return TRUE;
}

/**
 * Implementation of stroke_attribute_t.create_pool_enumerator
 */
static enumerator_t* create_pool_enumerator(private_stroke_attribute_t *this)
{
	this->mutex->lock(this->mutex);
	return enumerator_create_filter(this->pools->create_enumerator(this->pools),
									(void*)pool_filter,
									this->mutex, (void*)this->mutex->unlock);
}

/**
 * lease enumerator
 */
typedef struct {
	/** implemented enumerator interface */
	enumerator_t public;
	/** inner hash-table enumerator */
	enumerator_t *inner;
	/** enumerated pool */
	pool_t *pool;
	/** mutex to unlock on destruction */
	mutex_t *mutex;
	/** currently enumerated lease address */
	host_t *current;
} lease_enumerator_t;

/**
 * Implementation of lease_enumerator_t.enumerate
 */
static bool lease_enumerate(lease_enumerator_t *this, identification_t **id_out,
							host_t **addr_out, bool *online)
{
	identification_t *id;
	uintptr_t offset;

	DESTROY_IF(this->current);
	this->current = NULL;

	if (this->inner->enumerate(this->inner, &id, NULL))
	{
		offset = (uintptr_t)this->pool->online->get(this->pool->online, id);
		if (offset)
		{
			*id_out = id;
			*addr_out = this->current = offset2host(this->pool, offset);
			*online = TRUE;
			return TRUE;
		}
		offset = (uintptr_t)this->pool->offline->get(this->pool->offline, id);
		if (offset)
		{
			*id_out = id;
			*addr_out = this->current = offset2host(this->pool, offset);
			*online = FALSE;
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Implementation of lease_enumerator_t.destroy
 */
static void lease_enumerator_destroy(lease_enumerator_t *this)
{
	DESTROY_IF(this->current);
	this->inner->destroy(this->inner);
	this->mutex->unlock(this->mutex);
	free(this);
}

/**
 * Implementation of stroke_attribute_t.create_lease_enumerator
 */
static enumerator_t* create_lease_enumerator(private_stroke_attribute_t *this,
											 char *pool)
{
	lease_enumerator_t *enumerator;

	this->mutex->lock(this->mutex);
	enumerator = malloc_thing(lease_enumerator_t);
	enumerator->pool = find_pool(this, pool);
	if (!enumerator->pool)
	{
		this->mutex->unlock(this->mutex);
		free(enumerator);
		return NULL;
	}
	enumerator->public.enumerate = (void*)lease_enumerate;
	enumerator->public.destroy = (void*)lease_enumerator_destroy;
	enumerator->inner = enumerator->pool->ids->create_enumerator(enumerator->pool->ids);
	enumerator->mutex = this->mutex;
	enumerator->current = NULL;
	return &enumerator->public;
}

/**
 * Implementation of stroke_attribute_t.destroy
 */
static void destroy(private_stroke_attribute_t *this)
{
	this->mutex->destroy(this->mutex);
	this->pools->destroy_function(this->pools, (void*)pool_destroy);
	free(this);
}

/*
 * see header file
 */
stroke_attribute_t *stroke_attribute_create()
{
	private_stroke_attribute_t *this = malloc_thing(private_stroke_attribute_t);

	this->public.provider.acquire_address = (host_t*(*)(attribute_provider_t *this, char*, identification_t *,host_t *))acquire_address;
	this->public.provider.release_address = (bool(*)(attribute_provider_t *this, char*,host_t *, identification_t*))release_address;
	this->public.provider.create_attribute_enumerator = (enumerator_t*(*)(attribute_provider_t*, identification_t *id, host_t *vip))enumerator_create_empty;
	this->public.add_pool = (void(*)(stroke_attribute_t*, stroke_msg_t *msg))add_pool;
	this->public.del_pool = (void(*)(stroke_attribute_t*, stroke_msg_t *msg))del_pool;
	this->public.create_pool_enumerator = (enumerator_t*(*)(stroke_attribute_t*))create_pool_enumerator;
	this->public.create_lease_enumerator = (enumerator_t*(*)(stroke_attribute_t*, char *pool))create_lease_enumerator;
	this->public.destroy = (void(*)(stroke_attribute_t*))destroy;

	this->pools = linked_list_create();
	this->mutex = mutex_create(MUTEX_TYPE_RECURSIVE);

	return &this->public;
}

