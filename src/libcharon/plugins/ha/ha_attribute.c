/*
 * Copyright (C) 2018-2026 Tobias Brunner
 * Copyright (C) 2010 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
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

#include "ha_attribute.h"

#include <collections/array.h>
#include <collections/hashtable.h>
#include <collections/linked_list.h>
#include <threading/mutex.h>

typedef struct private_ha_attribute_t private_ha_attribute_t;

/**
 * Private data of an ha_attribute_t object.
 */
struct private_ha_attribute_t {

	/**
	 * Public ha_attribute_t interface.
	 */
	ha_attribute_t public;

	/**
	 * List of pools, pool_t
	 */
	linked_list_t *pools;

	/**
	 * Mutex to lock mask
	 */
	mutex_t *mutex;

	/**
	 * Kernel helper
	 */
	ha_kernel_t *kernel;

	/**
	 * Segment responsibility
	 */
	ha_segments_t *segments;
};

/**
 * In-memory pool.
 */
typedef struct {
	/** name of the pool */
	char *name;
	/** base address of pool */
	host_t *base;
	/** total number of addresses in this pool */
	int size;
	/** bitmask for address usage */
	u_char *mask;
	/** identity/lease table (identification_t -> entry_t) */
	hashtable_t *leases;
} pool_t;

/**
 * Leases for a specific identity
 */
typedef struct {
	/** peer identity (key) */
	identification_t *id;
	/** individual leases (lease_t) */
	array_t *leases;
} entry_t;

/**
 * Hashtable hash function
 */
static u_int entry_hash(const void *key)
{
	identification_t *id = (identification_t*)key;
	return id->hash(id, 0);
}

/**
 * Hashtable equals function
 */
static bool entry_equals(const void *a, const void *b)
{
	identification_t *id = (identification_t*)a;
	return id->equals(id, (identification_t*)b);
}

/**
 * Lease entry for an offset
 */
typedef struct {
	/** offset of the address in the pool */
	int offset;
	/** IKE_SA ID that currently owns this lease */
	ike_sa_id_t *id;
	/** hash of the peer's address/port for make-before-break reauth */
	uint32_t hash;
} lease_t;

/**
 * Create a unique hash for a remote address
 */
static uint32_t hash_addr(host_t *addr)
{
	return chunk_hash_inc(addr->get_address(addr), addr->get_port(addr));
}

/**
 * Get or create the entry for an identity
 */
static entry_t *entry_get(pool_t *pool, identification_t *id)
{
	entry_t *entry;

	entry = pool->leases->get(pool->leases, id);
	if (!entry)
	{
		INIT(entry,
			.id = id->clone(id),
		);
		pool->leases->put(pool->leases, entry->id, entry);
	}
	return entry;
}

/**
 * Create a lease entry for an IKE_SA
 */
static lease_t *create_lease(int offset, ike_sa_t *ike_sa)
{
	lease_t *this;
	ike_sa_id_t *id;

	id = ike_sa->get_id(ike_sa);

	INIT(this,
		.offset = offset,
		.id = id->clone(id),
		.hash = hash_addr(ike_sa->get_other_host(ike_sa)),
	);
	return this;
}

/**
 * Destroy a lease
 */
static void lease_destroy(lease_t *this)
{
	this->id->destroy(this->id);
	free(this);
}

/**
 * Destroy an identity entry and all leases
 */
static void entry_destroy(entry_t *this)
{
	array_destroy_function(this->leases, (void*)lease_destroy, NULL);
	this->id->destroy(this->id);
	free(this);
}

/**
 * Clean up a pool entry
 */
static void pool_destroy(pool_t *pool)
{
	pool->leases->destroy_function(pool->leases, (void*)entry_destroy);
	pool->base->destroy(pool->base);
	free(pool->name);
	free(pool->mask);
	free(pool);
}

/**
 * convert a pool offset to an address
 */
static host_t* offset2host(pool_t *pool, int offset)
{
	chunk_t addr;
	host_t *host;
	uint32_t *pos;

	if (offset >= pool->size)
	{
		return NULL;
	}

	addr = chunk_clone(pool->base->get_address(pool->base));
	if (pool->base->get_family(pool->base) == AF_INET6)
	{
		pos = (uint32_t*)(addr.ptr + 12);
	}
	else
	{
		pos = (uint32_t*)addr.ptr;
	}
	*pos = htonl(offset + ntohl(*pos));
	host = host_create_from_chunk(pool->base->get_family(pool->base), addr, 0);
	free(addr.ptr);
	return host;
}

/**
 * convert a host to a pool offset
 */
static int host2offset(pool_t *pool, host_t *addr)
{
	chunk_t host, base;
	uint32_t hosti, basei;

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
	hosti = ntohl(*(uint32_t*)(host.ptr));
	basei = ntohl(*(uint32_t*)(base.ptr));
	if (hosti - basei >= pool->size)
	{
		return -1;
	}
	return hosti - basei;
}

/**
 * Check if the given offset is valid for the size of the pool
 */
static bool valid_offset(pool_t *pool, int offset)
{
	return offset > 0 && offset < pool->size - 1;
}

/**
 * Find a pool by its name
 */
static pool_t* get_pool(private_ha_attribute_t *this, char *name)
{
	enumerator_t *enumerator;
	pool_t *pool, *found = NULL;

	enumerator = this->pools->create_enumerator(this->pools);
	while (enumerator->enumerate(enumerator, &pool))
	{
		if (streq(name, pool->name))
		{
			found = pool;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * Find the responsible pool (if any) and determine the offset for the given
 * virtual IP
 */
static pool_t *get_pool_by_vip(private_ha_attribute_t *this, host_t *vip,
							   int *offset)
{
	enumerator_t *enumerator;
	pool_t *pool;

	enumerator = this->pools->create_enumerator(this->pools);
	while (enumerator->enumerate(enumerator, &pool))
	{
		if (pool->base->get_family(pool->base) != vip->get_family(vip))
		{
			continue;
		}
		*offset = host2offset(pool, vip);
		if (!valid_offset(pool, *offset))
		{
			continue;
		}
		enumerator->destroy(enumerator);
		return pool;
	}
	enumerator->destroy(enumerator);
	return NULL;
}

/**
 * Check if we are responsible for an offset
 */
static bool responsible_for(private_ha_attribute_t *this, int offset)
{
	u_int segment;

	segment = offset % this->segments->count(this->segments) + 1;
	return this->segments->is_active(this->segments, segment);
}

/**
 * Find a lease by offset and the IKE_SA ID, if omitted, finds the first
 * lease of that offset
 */
static lease_t *find_lease(entry_t *entry, int offset, ike_sa_id_t *id,
						   int *index)
{
	lease_t *lease;
	int i;

	for (i = 0; i < array_count(entry->leases); i++)
	{
		array_get(entry->leases, i, &lease);

		if (lease->offset == offset &&
			(!id || lease->id->equals(lease->id, id)))
		{
			if (index)
			{
				*index = i;
			}
			return lease;
		}
	}
	return NULL;
}

/**
 * Find a lease by offset that is not owned by the given IKE_SA
 */
static lease_t *find_lease_other(entry_t *entry, int offset, ike_sa_id_t *id,
								 int *index)
{
	lease_t *lease;
	int i;

	for (i = 0; i < array_count(entry->leases); i++)
	{
		array_get(entry->leases, i, &lease);

		if (lease->offset == offset && !lease->id->equals(lease->id, id))
		{
			if (index)
			{
				*index = i;
			}
			return lease;
		}
	}
	return NULL;
}

/**
 * Release the lease at the given index, clears the offset if no further
 * references are found (returns TRUE in that case)
 */
static bool release_lease(pool_t *pool, entry_t *entry, int index)
{
	lease_t *lease;
	bool cleared = FALSE;

	array_remove(entry->leases, index, &lease);
	if (!find_lease(entry, lease->offset, NULL, NULL))
	{
		pool->mask[lease->offset / 8] &= ~(1 << (lease->offset % 8));
		cleared = TRUE;
	}
	lease_destroy(lease);
	return cleared;
}

/**
 * Remove and destroy an identity entry if there are no leases
 */
static void remove_entry_if_empty(pool_t *pool, entry_t *entry)
{
	if (!array_count(entry->leases))
	{
		pool->leases->remove(pool->leases, entry->id);
		entry_destroy(entry);
	}
}

/**
 * Reassign an online lease for the current peer during a make-before-break
 * reauthentication
 */
static host_t *acquire_online(private_ha_attribute_t *this,
							  linked_list_t *pools, ike_sa_t *ike_sa,
							  host_t *requested)
{
	enumerator_t *enumerator;
	pool_t *pool = NULL;
	entry_t *entry;
	lease_t *lease, *found = NULL;
	identification_t *id;
	ike_sa_id_t *sa;
	int offset = -1, i;
	u_int hash;
	char *name;
	bool is_any;
	host_t *address = NULL;

	id = ike_sa->get_other_eap_id(ike_sa);
	sa = ike_sa->get_id(ike_sa);
	hash = hash_addr(ike_sa->get_other_host(ike_sa));
	is_any = requested->is_anyaddr(requested);

	enumerator = pools->create_enumerator(pools);
	while (enumerator->enumerate(enumerator, &name))
	{
		pool = get_pool(this, name);
		if (!pool ||
			pool->base->get_family(pool->base) !=
			requested->get_family(requested))
		{
			continue;
		}
		if (!is_any)
		{
			offset = host2offset(pool, requested);
			if (!valid_offset(pool, offset) ||
				!responsible_for(this, offset))
			{
				continue;
			}
		}
		entry = pool->leases->get(pool->leases, id);
		if (!entry)
		{
			continue;
		}
		for (i = 0; i < array_count(entry->leases); i++)
		{
			array_get(entry->leases, i, &lease);

			if ((offset == -1 || offset == lease->offset) &&
				valid_offset(pool, lease->offset) &&
				responsible_for(this, lease->offset) &&
				lease->hash == hash &&
				!find_lease(entry, lease->offset, sa, NULL) &&
				(pool->mask[lease->offset / 8] & (1 << (lease->offset % 8))))
			{
				found = lease;
				break;
			}
		}
		if (found)
		{
			lease = create_lease(found->offset, ike_sa);
			array_insert_create(&entry->leases, ARRAY_TAIL, lease);
			address = offset2host(pool, found->offset);
			DBG1(DBG_CFG, "reassigned address %H to '%Y' from HA pool '%s'",
				 address, id, name);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return address;
}

METHOD(attribute_provider_t, acquire_address, host_t*,
	private_ha_attribute_t *this, linked_list_t *pools, ike_sa_t *ike_sa,
	host_t *requested)
{
	enumerator_t *enumerator;
	identification_t *id;
	pool_t *pool = NULL;
	entry_t *entry;
	lease_t *lease;
	int offset = -1, tmp_offset, byte, bit;
	host_t *address = NULL;
	char *name;

	this->mutex->lock(this->mutex);

	/* reacquire a lease already owned by the same peer */
	address = acquire_online(this, pools, ike_sa, requested);
	if (address)
	{
		this->mutex->unlock(this->mutex);
		return address;
	}

	id = ike_sa->get_other_eap_id(ike_sa);
	enumerator = pools->create_enumerator(pools);
	while (enumerator->enumerate(enumerator, &name))
	{
		pool = get_pool(this, name);
		if (!pool)
		{
			continue;
		}
		if (pool->base->get_family(pool->base) !=
			requested->get_family(requested))
		{
			continue;
		}
		for (byte = 0; byte < pool->size / 8; byte++)
		{
			if (pool->mask[byte] != 0xFF)
			{
				for (bit = 0; bit < 8; bit++)
				{
					tmp_offset = byte * 8 + bit;
					if (valid_offset(pool, tmp_offset) &&
						!(pool->mask[byte] & 1 << bit) &&
						responsible_for(this, tmp_offset))
					{
						offset = tmp_offset;
						pool->mask[byte] |= 1 << bit;
						entry = entry_get(pool, id);
						lease = create_lease(offset, ike_sa);
						array_insert_create(&entry->leases, ARRAY_TAIL, lease);
						break;
					}
				}
			}
			if (offset != -1)
			{
				break;
			}
		}
		if (offset == -1)
		{
			DBG1(DBG_CFG, "no address belonging to a responsible segment left "
				 "in HA pool '%s'", name);
		}
		else
		{
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (offset != -1)
	{
		address = offset2host(pool, offset);
		DBG1(DBG_CFG, "acquired address %H for '%Y' from HA pool '%s'",
			 address, id, name);
	}
	this->mutex->unlock(this->mutex);
	return address;
}

METHOD(attribute_provider_t, release_address, bool,
	private_ha_attribute_t *this, linked_list_t *pools, host_t *address,
	ike_sa_t *ike_sa)
{
	enumerator_t *enumerator;
	identification_t *id;
	pool_t *pool;
	entry_t *entry;
	lease_t *lease;
	int offset, index;
	char *name;
	bool found = FALSE;

	id = ike_sa->get_other_eap_id(ike_sa);

	enumerator = pools->create_enumerator(pools);
	this->mutex->lock(this->mutex);
	while (enumerator->enumerate(enumerator, &name))
	{
		pool = get_pool(this, name);
		if (!pool ||
			pool->base->get_family(pool->base) != address->get_family(address))
		{
			continue;
		}
		offset = host2offset(pool, address);
		if (!valid_offset(pool, offset))
		{
			continue;
		}
		entry = pool->leases->get(pool->leases, id);
		if (!entry)
		{
			continue;
		}
		lease = find_lease(entry, offset, ike_sa->get_id(ike_sa), &index);
		if (!lease)
		{
			continue;
		}
		if (release_lease(pool, entry, index))
		{
			DBG1(DBG_CFG, "released address %H for '%Y' to HA pool '%s'",
				 address, id, name);
		}
		else
		{
			DBG2(DBG_CFG, "address %H released by '%Y' still in use in HA "
				 "pool '%s'", address, id, name);
		}
		remove_entry_if_empty(pool, entry);
		found = TRUE;
		break;
	}
	this->mutex->unlock(this->mutex);
	enumerator->destroy(enumerator);

	return found;
}

METHOD(ha_attribute_t, reserve, void,
	private_ha_attribute_t *this, ike_sa_t *ike_sa, char *name, host_t *address)
{
	identification_t *id;
	pool_t *pool;
	entry_t *entry;
	lease_t *lease;
	int offset;

	id = ike_sa->get_other_eap_id(ike_sa);

	this->mutex->lock(this->mutex);
	pool = get_pool(this, name);
	if (pool)
	{
		offset = host2offset(pool, address);
		if (valid_offset(pool, offset))
		{
			pool->mask[offset / 8] |= 1 << (offset % 8);
			entry = entry_get(pool, id);
			if (!find_lease(entry, offset, ike_sa->get_id(ike_sa), NULL))
			{
				lease = create_lease(offset, ike_sa);
				array_insert_create(&entry->leases, ARRAY_TAIL, lease);
			}
			DBG1(DBG_CFG, "reserved address %H for '%Y' in HA pool '%s'",
				 address, id, name);
		}
	}
	this->mutex->unlock(this->mutex);
}

METHOD(ha_attribute_t, migrate, void,
	private_ha_attribute_t *this, ike_sa_t *old, ike_sa_t *new)
{
	enumerator_t *vips;
	ike_sa_id_t *old_id, *new_id;
	identification_t *id;
	host_t *vip;
	pool_t *pool;
	entry_t *entry;
	lease_t *lease;
	int offset;

	old_id = old->get_id(old);
	new_id = new->get_id(new);
	if (old_id->equals(old_id, new_id))
	{
		return;
	}
	id = old->get_other_eap_id(old);

	this->mutex->lock(this->mutex);
	vips = new->create_virtual_ip_enumerator(new, FALSE);
	while (vips->enumerate(vips, &vip))
	{
		pool = get_pool_by_vip(this, vip, &offset);
		if (!pool)
		{
			continue;
		}
		entry = pool->leases->get(pool->leases, id);
		if (!entry)
		{
			continue;
		}
		lease = find_lease(entry, offset, old_id, NULL);
		if (lease)
		{
			lease->id->destroy(lease->id);
			lease->id = new_id->clone(new_id);
		}
	}
	vips->destroy(vips);
	this->mutex->unlock(this->mutex);
}

METHOD(ha_attribute_t, update, void,
	private_ha_attribute_t *this, ike_sa_t *ike_sa, host_t *remote)
{
	enumerator_t *pools;
	ike_sa_id_t *sa;
	identification_t *id;
	pool_t *pool;
	entry_t *entry;
	lease_t *lease;
	u_int hash;
	int i;

	id = ike_sa->get_other_eap_id(ike_sa);
	sa = ike_sa->get_id(ike_sa);
	hash = hash_addr(remote);

	this->mutex->lock(this->mutex);
	pools = this->pools->create_enumerator(this->pools);
	while (pools->enumerate(pools, &pool))
	{
		entry = pool->leases->get(pool->leases, id);
		if (!entry)
		{
			continue;
		}
		for (i = 0; i < array_count(entry->leases); i++)
		{
			array_get(entry->leases, i, &lease);
			if (lease->id->equals(lease->id, sa))
			{
				lease->hash = hash;
			}
		}
	}
	pools->destroy(pools);
	this->mutex->unlock(this->mutex);
}

METHOD(ha_attribute_t, adopt, void,
	private_ha_attribute_t *this, ike_sa_t *ike_sa)
{
	enumerator_t *vips;
	ike_sa_id_t *sa;
	identification_t *id;
	host_t *vip;
	pool_t *pool;
	entry_t *entry;
	lease_t *lease;
	int offset;

	id = ike_sa->get_other_eap_id(ike_sa);
	sa = ike_sa->get_id(ike_sa);

	this->mutex->lock(this->mutex);
	vips = ike_sa->create_virtual_ip_enumerator(ike_sa, FALSE);
	while (vips->enumerate(vips, &vip))
	{
		pool = get_pool_by_vip(this, vip, &offset);
		if (!pool)
		{
			continue;
		}
		entry = pool->leases->get(pool->leases, id);
		if (!entry)
		{
			continue;
		}
		if (!find_lease(entry, offset, sa, NULL))
		{
			/* add a lease for the new SA, the old SA's lease is removed
			 * when that SA is destroyed */
			lease = create_lease(offset, ike_sa);
			array_insert_create(&entry->leases, ARRAY_TAIL, lease);
		}
	}
	vips->destroy(vips);
	this->mutex->unlock(this->mutex);
}

/**
 * Check if the given IKE_SA still owns the virtual IP that corresponds to the
 * offset
 */
static bool owns_offset(pool_t *pool, ike_sa_t *ike_sa, int offset)
{
	enumerator_t *vips;
	host_t *vip;
	bool found = FALSE;

	vips = ike_sa->create_virtual_ip_enumerator(ike_sa, FALSE);
	while (vips->enumerate(vips, &vip))
	{
		if (offset == host2offset(pool, vip))
		{
			found = TRUE;
			break;
		}
	}
	vips->destroy(vips);
	return found;
}

METHOD(ha_attribute_t, cleanup, void,
	private_ha_attribute_t *this, ike_sa_t *ike_sa)
{
	enumerator_t *pools;
	ike_sa_id_t *sa;
	identification_t *id;
	pool_t *pool;
	entry_t *entry;
	lease_t *lease;
	int i;

	id = ike_sa->get_other_eap_id(ike_sa);
	sa = ike_sa->get_id(ike_sa);

	this->mutex->lock(this->mutex);
	pools = this->pools->create_enumerator(this->pools);
	while (pools->enumerate(pools, &pool))
	{
		entry = pool->leases->get(pool->leases, id);
		if (!entry)
		{
			continue;
		}
		for (i = array_count(entry->leases) - 1; i >= 0; i--)
		{
			array_get(entry->leases, i, &lease);

			if (!lease->id->equals(lease->id, sa))
			{
				continue;
			}
			/* release the lease if another SA still owns the address or if the
			 * VIP got cleared from the SA (IKEv1 adoption), so it won't get
			 * released regularly */
			if (find_lease_other(entry, lease->offset, sa, NULL) ||
				!owns_offset(pool, ike_sa, lease->offset))
			{
				release_lease(pool, entry, i);
			}
		}
		remove_entry_if_empty(pool, entry);
	}
	pools->destroy(pools);
	this->mutex->unlock(this->mutex);
}

METHOD(ha_attribute_t, destroy, void,
	private_ha_attribute_t *this)
{
	this->pools->destroy_function(this->pools, (void*)pool_destroy);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * Load the configured pools.
 */
static void load_pools(private_ha_attribute_t *this)
{
	enumerator_t *enumerator;
	char *name, *net, *bits;
	host_t *base;
	int mask, maxbits;
	pool_t *pool;

	enumerator = lib->settings->create_key_value_enumerator(lib->settings,
												"%s.plugins.ha.pools", lib->ns);
	while (enumerator->enumerate(enumerator, &name, &net))
	{
		net = strdup(net);
		bits = strchr(net, '/');
		if (!bits)
		{
			DBG1(DBG_CFG, "invalid HA pool '%s' subnet, skipped", name);
			free(net);
			continue;
		}
		*bits++ = '\0';

		base = host_create_from_string(net, 0);
		mask = atoi(bits);
		free(net);
		if (!base || !mask)
		{
			DESTROY_IF(base);
			DBG1(DBG_CFG, "invalid HA pool '%s', skipped", name);
			continue;
		}
		maxbits = base->get_family(base) == AF_INET ? 32 : 128;
		mask = maxbits - mask;
		if (mask > 24)
		{
			mask = 24;
			DBG1(DBG_CFG, "size of HA pool '%s' limited to /%d",
				 name, maxbits - mask);
		}
		if (mask < 3)
		{
			DBG1(DBG_CFG, "HA pool '%s' too small, skipped", name);
			base->destroy(base);
			continue;
		}

		INIT(pool,
			.name = strdup(name),
			.base = base,
			.size = (1 << mask),
			.leases = hashtable_create(entry_hash, entry_equals, 8),
		);
		pool->mask = calloc(pool->size / 8, 1);
		/* do not use first/last address of pool */
		pool->mask[0] |= 0x01;
		pool->mask[pool->size / 8 - 1] |= 0x80;

		DBG1(DBG_CFG, "loaded HA pool '%s' %H/%d (%d addresses)",
			 pool->name, pool->base, maxbits - mask, pool->size - 2);
		this->pools->insert_last(this->pools, pool);
	}
	enumerator->destroy(enumerator);
}

/**
 * See header
 */
ha_attribute_t *ha_attribute_create(ha_kernel_t *kernel, ha_segments_t *segments)
{
	private_ha_attribute_t *this;

	INIT(this,
		.public = {
			.provider = {
				.acquire_address = _acquire_address,
				.release_address = _release_address,
				.create_attribute_enumerator = (void*)enumerator_create_empty,
			},
			.reserve = _reserve,
			.migrate = _migrate,
			.update = _update,
			.adopt = _adopt,
			.cleanup = _cleanup,
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.pools = linked_list_create(),
		.kernel = kernel,
		.segments = segments,
	);

	load_pools(this);

	return &this->public;
}
