/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
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

#include "ipsec.h"
#include "ipsec_sa_mgr.h"

#include <debug.h>
#include <library.h>
#include <processing/jobs/callback_job.h>
#include <threading/mutex.h>
#include <utils/hashtable.h>
#include <utils/linked_list.h>

typedef struct private_ipsec_sa_mgr_t private_ipsec_sa_mgr_t;

/**
 * Private additions to ipsec_sa_mgr_t.
 */
struct private_ipsec_sa_mgr_t {

	/**
	 * Public members of ipsec_sa_mgr_t.
	 */
	ipsec_sa_mgr_t public;

	/**
	 * Installed SAs
	 */
	linked_list_t *sas;

	/**
	 * SPIs allocated using get_spi()
	 */
	hashtable_t *allocated_spis;

	/**
	 * Mutex used to synchronize access to the SA manager
	 */
	mutex_t *mutex;

	/**
	 * RNG used to generate SPIs
	 */
	rng_t *rng;
};

/**
 * Helper struct for expiration events
 */
typedef struct {

	/**
	 * IPsec SA manager
	 */
	private_ipsec_sa_mgr_t *manager;

	/**
	 * SA that expired
	 */
	ipsec_sa_t *sa;

	/**
	 * 0 if this is a hard expire, otherwise the offset in s (soft->hard)
	 */
	u_int32_t hard_offset;

} ipsec_sa_expired_t;

/*
 * Used for the hash table of allocated SPIs
 */
static bool spi_equals(u_int32_t *spi, u_int32_t *other_spi)
{
	return *spi == *other_spi;
}

static u_int spi_hash(u_int32_t *spi)
{
	return chunk_hash(chunk_from_thing(*spi));
}

/**
 * Flushes all entries
 * Must be called with this->mutex held.
 */
static void flush_entries(private_ipsec_sa_mgr_t *this)
{
	enumerator_t *enumerator;
	ipsec_sa_t *current;

	DBG2(DBG_ESP, "flushing SAD");

	enumerator = this->sas->create_enumerator(this->sas);
	while (enumerator->enumerate(enumerator, (void**)&current))
	{
		this->sas->remove_at(this->sas, enumerator);
		current->destroy(current);
	}
	enumerator->destroy(enumerator);
}

/*
 * Different match functions to find SAs in the linked list
 */
static bool match_entry_by_ptr(ipsec_sa_t *sa, ipsec_sa_t *other)
{
	return sa == other;
}

static bool match_entry_by_spi_inbound(ipsec_sa_t *sa, u_int32_t spi,
									   bool inbound)
{
	return sa->get_spi(sa) == spi && sa->is_inbound(sa) == inbound;
}

static bool match_entry_by_spi_src_dst(ipsec_sa_t *sa, u_int32_t spi,
									   host_t *src, host_t *dst)
{
	return sa->match_by_spi_src_dst(sa, spi, src, dst);
}

/**
 * Callback for expiration events
 */
static job_requeue_t sa_expired(ipsec_sa_expired_t *expired)
{
	private_ipsec_sa_mgr_t *this = expired->manager;

	this->mutex->lock(this->mutex);
	if (this->sas->find_first(this->sas, (void*)match_entry_by_ptr,
							  NULL, expired->sa) == SUCCESS)
	{
		u_int32_t hard_offset = expired->hard_offset;
		ipsec_sa_t *sa = expired->sa;

		ipsec->events->expire(ipsec->events, sa->get_reqid(sa),
							  sa->get_protocol(sa), sa->get_spi(sa),
							  hard_offset == 0);
		if (hard_offset)
		{	/* soft limit reached, schedule hard expire */
			expired->hard_offset = 0;
			this->mutex->unlock(this->mutex);
			return JOB_RESCHEDULE(hard_offset);
		}
		/* hard limit reached */
		this->sas->remove(this->sas, sa, NULL);
		sa->destroy(sa);
	}
	this->mutex->unlock(this->mutex);
	return JOB_REQUEUE_NONE;
}

/**
 * Schedule a job to handle IPsec SA expiration
 */
static void schedule_expiration(private_ipsec_sa_mgr_t *this,
								ipsec_sa_t *sa)
{
	lifetime_cfg_t *lifetime = sa->get_lifetime(sa);
	ipsec_sa_expired_t *expired;
	callback_job_t *job;
	u_int32_t timeout;

	INIT(expired,
		.manager = this,
		.sa = sa,
	);

	/* schedule a rekey first, a hard timeout will be scheduled then, if any */
	expired->hard_offset = lifetime->time.life - lifetime->time.rekey;
	timeout = lifetime->time.rekey;

	if (lifetime->time.life <= lifetime->time.rekey ||
		lifetime->time.rekey == 0)
	{	/* no rekey, schedule hard timeout */
		expired->hard_offset = 0;
		timeout = lifetime->time.life;
	}

	job = callback_job_create((callback_job_cb_t)sa_expired, expired,
							  (callback_job_cleanup_t)free, NULL);
	lib->scheduler->schedule_job(lib->scheduler, (job_t*)job, timeout);
}

/**
 * Remove all allocated SPIs
 */
static void flush_allocated_spis(private_ipsec_sa_mgr_t *this)
{
	enumerator_t *enumerator;
	u_int32_t *current;

	DBG2(DBG_ESP, "flushing allocated SPIs");
	enumerator = this->allocated_spis->create_enumerator(this->allocated_spis);
	while (enumerator->enumerate(enumerator, NULL, (void**)&current))
	{
		this->allocated_spis->remove_at(this->allocated_spis, enumerator);
		DBG2(DBG_ESP, "  removed allocated SPI %.8x", ntohl(*current));
		free(current);
	}
	enumerator->destroy(enumerator);
}

/**
 * Pre-allocate an SPI for an inbound SA
 */
static bool allocate_spi(private_ipsec_sa_mgr_t *this, u_int32_t spi)
{
	u_int32_t *spi_alloc;

	if (this->allocated_spis->get(this->allocated_spis, &spi) ||
		this->sas->find_first(this->sas, (void*)match_entry_by_spi_inbound,
							  NULL, spi, TRUE) == SUCCESS)
	{
		return FALSE;
	}
	spi_alloc = malloc_thing(u_int32_t);
	*spi_alloc = spi;
	this->allocated_spis->put(this->allocated_spis, spi_alloc, spi_alloc);
	return TRUE;
}

METHOD(ipsec_sa_mgr_t, get_spi, status_t,
	private_ipsec_sa_mgr_t *this, host_t *src, host_t *dst, u_int8_t protocol,
	u_int32_t reqid, u_int32_t *spi)
{
	u_int32_t spi_new;

	DBG2(DBG_ESP, "allocating SPI for reqid {%u}", reqid);

	this->mutex->lock(this->mutex);
	if (!this->rng)
	{
		this->rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
		if (!this->rng)
		{
			this->mutex->unlock(this->mutex);
			DBG1(DBG_ESP, "failed to create RNG for SPI generation");
			return FAILED;
		}
	}

	do
	{
		if (!this->rng->get_bytes(this->rng, sizeof(spi_new),
								 (u_int8_t*)&spi_new))
		{
			this->mutex->unlock(this->mutex);
			DBG1(DBG_ESP, "failed to allocate SPI for reqid {%u}", reqid);
			return FAILED;
		}
		/* make sure the SPI is valid (not in range 0-255) */
		spi_new |= 0x00000100;
		spi_new = htonl(spi_new);
	}
	while (!allocate_spi(this, spi_new));
	this->mutex->unlock(this->mutex);

	*spi = spi_new;

	DBG2(DBG_ESP, "allocated SPI %.8x for reqid {%u}", ntohl(*spi), reqid);
	return SUCCESS;
}

METHOD(ipsec_sa_mgr_t, add_sa, status_t,
	private_ipsec_sa_mgr_t *this, host_t *src, host_t *dst, u_int32_t spi,
	u_int8_t protocol, u_int32_t reqid,	mark_t mark, u_int32_t tfc,
	lifetime_cfg_t *lifetime, u_int16_t enc_alg, chunk_t enc_key,
	u_int16_t int_alg, chunk_t int_key, ipsec_mode_t mode, u_int16_t ipcomp,
	u_int16_t cpi, bool encap, bool esn, bool inbound,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts)
{
	ipsec_sa_t *sa_new;

	DBG2(DBG_ESP, "adding SAD entry with SPI %.8x and reqid {%u}",
		 ntohl(spi), reqid);
	DBG2(DBG_ESP, "  using encryption algorithm %N with key size %d",
		 encryption_algorithm_names, enc_alg, enc_key.len * 8);
	DBG2(DBG_ESP, "  using integrity algorithm %N with key size %d",
		 integrity_algorithm_names, int_alg, int_key.len * 8);

	sa_new = ipsec_sa_create(spi, src, dst, protocol, reqid, mark, tfc,
							 lifetime, enc_alg, enc_key, int_alg, int_key, mode,
							 ipcomp, cpi, encap, esn, inbound, src_ts, dst_ts);
	if (!sa_new)
	{
		DBG1(DBG_ESP, "failed to create SAD entry");
		return FAILED;
	}

	this->mutex->lock(this->mutex);

	if (inbound)
	{	/* remove any pre-allocated SPIs */
		u_int32_t *spi_alloc;

		spi_alloc = this->allocated_spis->remove(this->allocated_spis, &spi);
		free(spi_alloc);
	}

	if (this->sas->find_first(this->sas, (void*)match_entry_by_spi_src_dst,
							  NULL, spi, src, dst) == SUCCESS)
	{
		this->mutex->unlock(this->mutex);
		DBG1(DBG_ESP, "failed to install SAD entry: already installed");
		sa_new->destroy(sa_new);
		return FAILED;
	}

	schedule_expiration(this, sa_new);
	this->sas->insert_last(this->sas, sa_new);

	this->mutex->unlock(this->mutex);
	return SUCCESS;
}

METHOD(ipsec_sa_mgr_t, del_sa, status_t,
	private_ipsec_sa_mgr_t *this, host_t *src, host_t *dst, u_int32_t spi,
	u_int8_t protocol, u_int16_t cpi, mark_t mark)
{
	ipsec_sa_t *current, *found = NULL;
	enumerator_t *enumerator;

	this->mutex->lock(this->mutex);
	enumerator = this->sas->create_enumerator(this->sas);
	while (enumerator->enumerate(enumerator, (void**)&current))
	{
		if (match_entry_by_spi_src_dst(current, spi, src, dst))
		{
			this->sas->remove_at(this->sas, enumerator);
			found = current;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	if (found)
	{
		DBG2(DBG_ESP, "deleted %sbound SAD entry with SPI %.8x",
			 found->is_inbound(found) ? "in" : "out", ntohl(spi));
		found->destroy(found);
		return SUCCESS;
	}
	return FAILED;
}

METHOD(ipsec_sa_mgr_t, flush_sas, status_t,
	private_ipsec_sa_mgr_t *this)
{
	this->mutex->lock(this->mutex);
	flush_entries(this);
	this->mutex->unlock(this->mutex);
	return SUCCESS;
}

METHOD(ipsec_sa_mgr_t, destroy, void,
	private_ipsec_sa_mgr_t *this)
{
	this->mutex->lock(this->mutex);
	flush_entries(this);
	flush_allocated_spis(this);
	this->mutex->unlock(this->mutex);

	this->allocated_spis->destroy(this->allocated_spis);
	this->sas->destroy(this->sas);

	this->mutex->destroy(this->mutex);
	DESTROY_IF(this->rng);
	free(this);
}

/**
 * Described in header.
 */
ipsec_sa_mgr_t *ipsec_sa_mgr_create()
{
	private_ipsec_sa_mgr_t *this;

	INIT(this,
		.public = {
			.get_spi = _get_spi,
			.add_sa = _add_sa,
			.del_sa = _del_sa,
			.flush_sas = _flush_sas,
			.destroy = _destroy,
		},
		.sas = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.allocated_spis = hashtable_create((hashtable_hash_t)spi_hash,
										   (hashtable_equals_t)spi_equals, 16),
	);

	return &this->public;
}
