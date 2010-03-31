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

#include "mem_pool.h"

#include <debug.h>
#include <utils/hashtable.h>
#include <threading/rwlock.h>

#define POOL_LIMIT (sizeof(uintptr_t)*8)

typedef struct private_mem_pool_t private_mem_pool_t;

/**
 * private data of mem_pool_t
 */
struct private_mem_pool_t {
	/**
	 * public interface
	 */
	mem_pool_t public;

	/**
	 * name of the pool
	 */
	char *name;

	/**
	 * base address of the pool
	 */
	host_t *base;

	/**
	 * size of the pool
	 */
	u_int size;

	/**
	 * next unused address
	 */
	u_int unused;

	/**
	 * hashtable [identity => offset], for online leases
	 */
	hashtable_t *online;

	/**
	 * hashtable [identity => offset], for offline leases
	 */
	hashtable_t *offline;

	/**
	 * hashtable [identity => identity], handles identity references
	 */
	hashtable_t *ids;

	/**
	 * lock to safely access the pool
	 */
	rwlock_t *lock;
};

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
 * convert a pool offset to an address
 */
static host_t* offset2host(private_mem_pool_t *pool, int offset)
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
static int host2offset(private_mem_pool_t *pool, host_t *addr)
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

METHOD(mem_pool_t, get_name, const char*,
	   private_mem_pool_t *this)
{
	return this->name;
}

METHOD(mem_pool_t, get_size, u_int,
	   private_mem_pool_t *this)
{
	return this->size;
}

METHOD(mem_pool_t, get_online, u_int,
	   private_mem_pool_t *this)
{
	u_int count;
	this->lock->read_lock(this->lock);
	count = this->online->get_count(this->online);
	this->lock->unlock(this->lock);
	return count;
}

METHOD(mem_pool_t, get_offline, u_int,
	   private_mem_pool_t *this)
{
	u_int count;
	this->lock->read_lock(this->lock);
	count = this->offline->get_count(this->offline);
	this->lock->unlock(this->lock);
	return count;
}

METHOD(mem_pool_t, acquire_address, host_t*,
	   private_mem_pool_t *this, identification_t *id, host_t *requested)
{
	uintptr_t offset = 0;
	enumerator_t *enumerator;
	identification_t *old_id;

	/* if the pool is empty (e.g. in the %config case) we simply return the
	 * requested address */
	if (this->size == 0)
	{
		return requested->clone(requested);
	}

	if (!requested->is_anyaddr(requested) &&
		requested->get_family(requested) !=
		this->base->get_family(this->base))
	{
		DBG1(DBG_CFG, "IP pool address family mismatch");
		return NULL;
	}

	this->lock->write_lock(this->lock);
	while (TRUE)
	{
		/* check for a valid offline lease, refresh */
		offset = (uintptr_t)this->offline->remove(this->offline, id);
		if (offset)
		{
			id = this->ids->get(this->ids, id);
			if (id)
			{
				DBG1(DBG_CFG, "reassigning offline lease to '%Y'", id);
				this->online->put(this->online, id, (void*)offset);
				break;
			}
		}

		/* check for a valid online lease, reassign */
		offset = (uintptr_t)this->online->get(this->online, id);
		if (offset && offset == host2offset(this, requested))
		{
			DBG1(DBG_CFG, "reassigning online lease to '%Y'", id);
			break;
		}

		if (this->unused < this->size)
		{
			/* assigning offset, starting by 1. Handling 0 in hashtable
			 * is difficult. */
			offset = ++this->unused;
			id = id->clone(id);
			this->ids->put(this->ids, id, id);
			this->online->put(this->online, id, (void*)offset);
			DBG1(DBG_CFG, "assigning new lease to '%Y'", id);
			break;
		}

		/* no more addresses, replace the first found offline lease */
		enumerator = this->offline->create_enumerator(this->offline);
		if (enumerator->enumerate(enumerator, &old_id, &offset))
		{
			offset = (uintptr_t)this->offline->remove(this->offline, old_id);
			if (offset)
			{
				/* destroy reference to old ID */
				old_id = this->ids->remove(this->ids, old_id);
				DBG1(DBG_CFG, "reassigning existing offline lease by '%Y'"
					 " to '%Y'", old_id, id);
				if (old_id)
				{
					old_id->destroy(old_id);
				}
				id = id->clone(id);
				this->ids->put(this->ids, id, id);
				this->online->put(this->online, id, (void*)offset);
				enumerator->destroy(enumerator);
				break;
			}
		}
		enumerator->destroy(enumerator);

		DBG1(DBG_CFG, "pool '%s' is full, unable to assign address",
			 this->name);
		break;
	}
	this->lock->unlock(this->lock);

	if (offset)
	{
		return offset2host(this, offset);
	}
	return NULL;
}

METHOD(mem_pool_t, release_address, bool,
	   private_mem_pool_t *this, host_t *address, identification_t *id)
{
	bool found = FALSE;
	if (this->size != 0)
	{
		uintptr_t offset;
		this->lock->write_lock(this->lock);
		offset = (uintptr_t)this->online->remove(this->online, id);
		if (offset)
		{
			id = this->ids->get(this->ids, id);
			if (id)
			{
				DBG1(DBG_CFG, "lease %H by '%Y' went offline", address, id);
				this->offline->put(this->offline, id, (void*)offset);
				found = TRUE;
			}
		}
		this->lock->unlock(this->lock);
	}
	return found;
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
	private_mem_pool_t *pool;
	/** currently enumerated lease address */
	host_t *current;
} lease_enumerator_t;

METHOD(enumerator_t, lease_enumerate, bool,
	   lease_enumerator_t *this, identification_t **id_out, host_t **addr_out,
	   bool *online)
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

METHOD(enumerator_t, lease_enumerator_destroy, void,
	   lease_enumerator_t *this)
{
	DESTROY_IF(this->current);
	this->inner->destroy(this->inner);
	this->pool->lock->unlock(this->pool->lock);
	free(this);
}

METHOD(mem_pool_t, create_lease_enumerator, enumerator_t*,
	   private_mem_pool_t *this)
{
	lease_enumerator_t *enumerator;
	this->lock->read_lock(this->lock);
	INIT(enumerator,
		.public = {
			.enumerate = (void*)_lease_enumerate,
			.destroy = (void*)_lease_enumerator_destroy,
		},
		.pool = this,
		.inner = this->ids->create_enumerator(this->ids),
	);
	return &enumerator->public;
}

METHOD(mem_pool_t, destroy, void,
	   private_mem_pool_t *this)
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
	this->lock->destroy(this->lock);
	DESTROY_IF(this->base);
	free(this->name);
	free(this);
}

/**
 * Described in header
 */
mem_pool_t *mem_pool_create(char *name, host_t *base, int bits)
{
	private_mem_pool_t *this;

	INIT(this,
		.public = {
			.get_name = _get_name,
			.get_size = _get_size,
			.get_online = _get_online,
			.get_offline = _get_offline,
			.acquire_address = _acquire_address,
			.release_address = _release_address,
			.create_lease_enumerator = _create_lease_enumerator,
			.destroy = _destroy,
		},
		.name = strdup(name),
		.online = hashtable_create((hashtable_hash_t)id_hash,
								   (hashtable_equals_t)id_equals, 16),
		.offline = hashtable_create((hashtable_hash_t)id_hash,
									(hashtable_equals_t)id_equals, 16),
		.ids = hashtable_create((hashtable_hash_t)id_hash,
								(hashtable_equals_t)id_equals, 16),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	if (base)
	{
		int addr_bits = base->get_family(base) == AF_INET ? 32 : 128;
		/* net bits -> host bits */
		bits = addr_bits - bits;
		if (bits > POOL_LIMIT)
		{
			bits = POOL_LIMIT;
			DBG1(DBG_CFG, "virtual IP pool too large, limiting to %H/%d",
				 base, addr_bits - bits);
		}
		this->size = 1 << (bits);

		if (this->size > 2)
		{	/* do not use first and last addresses of a block */
			this->unused++;
			this->size--;
		}
		this->base = base->clone(base);
	}

	return &this->public;
}

