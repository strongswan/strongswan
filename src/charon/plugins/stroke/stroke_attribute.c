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

#include "stroke_attribute.h"

#include <daemon.h>
#include <utils/linked_list.h>
#include <utils/mutex.h>

#define POOL_LIMIT 16

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
	/** number of entries in the pool */
	int count;
	/** array of in-use flags, TODO: use bit fields */
	u_int8_t *in_use;
} pool_t;

/**
 * destroy a pool_t
 */
static void pool_destroy(pool_t *this)
{
	this->base->destroy(this->base);
	free(this->name);
	free(this->in_use);
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
	
	if (offset > pool->count)
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
	if (hosti > basei + pool->count)
	{
		return -1;
	}
	return hosti - basei;
}

/**
 * Implementation of attribute_provider_t.acquire_address
 */
static host_t* acquire_address(private_stroke_attribute_t *this,
							   char *name, identification_t *id,
							   auth_info_t *auth, host_t *requested)
{
	pool_t *pool;
	host_t *host = NULL;
	int i;
	
	this->mutex->lock(this->mutex);
	pool = find_pool(this, name);
	if (pool)
	{
		if (requested && !requested->is_anyaddr(requested))
		{
			i = host2offset(pool, requested);
			if (i >= 0 && !pool->in_use[i])
			{
				pool->in_use[i] = TRUE;
				host = requested->clone(requested);
			}
		}
		if (!host)
		{
			for (i = 0; i < pool->count; i++)
			{
				if (!pool->in_use[i])
				{
					pool->in_use[i] = TRUE;
					host = offset2host(pool, i);
					break;
				}
			}
		}
	}
	this->mutex->unlock(this->mutex);
	return host;
}

/**
 * Implementation of attribute_provider_t.release_address
 */
static bool release_address(private_stroke_attribute_t *this,
							char *name, host_t *address)
{
	pool_t *pool;
	bool found = FALSE;
	int i;
	
	this->mutex->lock(this->mutex);
	pool = find_pool(this, name);
	if (pool)
	{
		i = host2offset(pool, address);
		if (i >= 0 && pool->in_use[i])
		{
			pool->in_use[i] = FALSE;
			found =TRUE;
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
	if (msg->add_conn.other.sourceip && msg->add_conn.other.sourceip_size)
	{
		pool_t *pool;
		u_int32_t bits;
		int family;
		
		DBG1(DBG_CFG, "adding virtual IP address pool '%s': %s/%d", 
			 msg->add_conn.name, msg->add_conn.other.sourceip, 
			 msg->add_conn.other.sourceip_size);
		
		pool = malloc_thing(pool_t);
		pool->base = host_create_from_string(msg->add_conn.other.sourceip, 0);
		if (!pool->base)
		{
			free(pool);
			DBG1(DBG_CFG, "virtual IP address invalid, discarded");
			return;
		}
		pool->name = strdup(msg->add_conn.name);
		family = pool->base->get_family(pool->base);
		bits = (family == AF_INET ? 32 : 128) - msg->add_conn.other.sourceip_size;
		if (bits > POOL_LIMIT)
		{
			bits = POOL_LIMIT;
			DBG1(DBG_CFG, "virtual IP pool to large, limiting to %s/%d",
				 msg->add_conn.other.sourceip,
				 (family == AF_INET ? 32 : 128) - bits);
		}
		pool->count = 1 << (bits);
		pool->in_use = calloc(pool->count, sizeof(u_int8_t));
		
		if (pool->count > 2)
		{	/* do not use first and last addresses of a block */
			pool->in_use[0] = TRUE;
			pool->in_use[pool->count-1] = TRUE;
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
	
	this->public.provider.acquire_address = (host_t*(*)(attribute_provider_t *this, char*, identification_t *,auth_info_t *, host_t *))acquire_address;
	this->public.provider.release_address = (bool(*)(attribute_provider_t *this, char*,host_t *))release_address;
	this->public.add_pool = (void(*)(stroke_attribute_t*, stroke_msg_t *msg))add_pool;
	this->public.del_pool = (void(*)(stroke_attribute_t*, stroke_msg_t *msg))del_pool;
	this->public.destroy = (void(*)(stroke_attribute_t*))destroy;
	
	this->pools = linked_list_create();
	this->mutex = mutex_create(MUTEX_DEFAULT);
	
	return &this->public;
}

