/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

/* Windows 7, for some fwpmu.h functionality */
#define _WIN32_WINNT 0x0601

#include "kernel_wfp_compat.h"
#include "kernel_wfp_ipsec.h"

#include <daemon.h>
#include <threading/mutex.h>
#include <collections/array.h>
#include <collections/hashtable.h>


typedef struct private_kernel_wfp_ipsec_t private_kernel_wfp_ipsec_t;

struct private_kernel_wfp_ipsec_t {

	/**
	 * Public interface
	 */
	kernel_wfp_ipsec_t public;

	/**
	 * Next SPI to allocate
	 */
	refcount_t nextspi;

	/**
	 * SAD/SPD entries, as reqid => entry_t
	 */
	hashtable_t *entries;

	/**
	 * SAD entry lookup, as sa_entry_t => entry_t
	 */
	hashtable_t *sas;

	/**
	 * Mutex for accessing entries
	 */
	mutex_t *mutex;

	/**
	 * WFP session handle
	 */
	HANDLE handle;
};

/**
 * Security association entry
 */
typedef struct {
	/** SPI for this SA */
	u_int32_t spi;
	/** destination host address for this SPI */
	host_t *dst;
	/** inbound or outbound SA? */
	bool inbound;
	struct {
		/** algorithm */
		u_int16_t alg;
		/** key */
		chunk_t key;
	} integ, encr;
} sa_entry_t;

/**
 * Destroy an SA entry
 */
static void sa_entry_destroy(sa_entry_t *sa)
{
	chunk_clear(&sa->integ.key);
	chunk_clear(&sa->encr.key);
	free(sa);
}

/**
 * Hash function for sas lookup table
 */
static u_int hash_sa(sa_entry_t *key)
{
	return chunk_hash_inc(chunk_from_thing(key->spi),
						  chunk_hash(key->dst->get_address(key->dst)));
}

/**
 * equals function for sas lookup table
 */
static bool equals_sa(sa_entry_t *a, sa_entry_t *b)
{
	return a->spi == b->spi && a->dst->ip_equals(a->dst, b->dst);
}

/**
 * Security policy entry
 */
typedef struct {
	/** policy source addresses */
	traffic_selector_t *src;
	/** policy destinaiton addresses */
	traffic_selector_t *dst;
	/** direction of policy, in|out */
	policy_dir_t direction;
} sp_entry_t;

/**
 * Destroy an SP entry
 */
static void sp_entry_destroy(sp_entry_t *sp)
{
	sp->src->destroy(sp->src);
	sp->dst->destroy(sp->dst);
	free(sp);
}

/**
 * Collection of SA/SP database entries for a reqid
 */
typedef struct {
	/** reqid of entry */
	u_int32_t reqid;
	/** outer address on local host */
	host_t *local;
	/** outer address on remote host */
	host_t *remote;
	/** associated security associations, as sa_entry_t* */
	array_t *sas;
	/** associated policies, as sp_entry_t* */
	array_t *sps;
	/** IPsec protocol, ESP|AH */
	u_int8_t protocol;
	/** IPsec mode, tunnel|transport */
	ipsec_mode_t mode;
	/** UDP encapsulation */
	bool encap;
} entry_t;

/**
 * Create a SA/SP entry set
 */
static entry_t *entry_create(u_int32_t reqid, host_t *local, host_t *remote,
							 u_int8_t protocol, ipsec_mode_t mode, bool encap)
{
	entry_t *entry;

	INIT(entry,
		.reqid = reqid,
		.sas = array_create(0, 0),
		.sps = array_create(0, 0),
		.local = local->clone(local),
		.remote = remote->clone(remote),
		.protocol = protocol,
		.mode = mode,
		.encap = encap,
	);
	return entry;
}

/**
 * Destroy a SA/SP entry set
 */
static void entry_destroy(entry_t *entry)
{
	array_destroy(entry->sas);
	array_destroy(entry->sps);
	entry->local->destroy(entry->local);
	entry->remote->destroy(entry->remote);
	free(entry);
}

/**
 * Get an entry, create if not exists. May fail if non-matching entry found
 */
static entry_t *get_or_create_entry(private_kernel_wfp_ipsec_t *this,
							u_int32_t reqid, host_t *local, host_t *remote,
							u_int8_t protocol, ipsec_mode_t mode, bool encap)
{
	entry_t *entry;

	entry = this->entries->get(this->entries, (void*)(uintptr_t)reqid);
	if (!entry)
	{
		entry = entry_create(reqid, local, remote, protocol, mode, encap);
		this->entries->put(this->entries, (void*)(uintptr_t)reqid, entry);
		return entry;
	}
	if (entry->protocol == protocol &&
		entry->mode == mode &&
		entry->local->ip_equals(entry->local, local) &&
		entry->remote->ip_equals(entry->remote, remote))
	{
		return entry;
	}
	return NULL;
}

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
	private_kernel_wfp_ipsec_t *this)
{
	return KERNEL_ESP_V3_TFC;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	u_int8_t protocol, u_int32_t reqid, u_int32_t *spi)
{
	*spi = ref_get(&this->nextspi);
	return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t reqid, u_int16_t *cpi)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int32_t reqid, mark_t mark,
	u_int32_t tfc, lifetime_cfg_t *lifetime, u_int16_t enc_alg, chunk_t enc_key,
	u_int16_t int_alg, chunk_t int_key, ipsec_mode_t mode, u_int16_t ipcomp,
	u_int16_t cpi, bool initiator, bool encap, bool esn, bool inbound,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts)
{
	status_t status = SUCCESS;
	host_t *local, *remote;
	entry_t *entry;
	sa_entry_t *sa;

	if (inbound)
	{
		local = dst;
		remote = src;
	}
	else
	{
		local = src;
		remote = dst;
	}

	this->mutex->lock(this->mutex);
	entry = get_or_create_entry(this, reqid, local, remote,
								protocol, mode, encap);
	if (entry)
	{
		INIT(sa,
			.spi = spi,
			.inbound = inbound,
			.dst = inbound ? entry->local : entry->remote,
			.encr = {
				.alg = enc_alg,
				.key = chunk_clone(enc_key),
			},
			.integ = {
				.alg = int_alg,
				.key = chunk_clone(int_key),
			},
		);
		array_insert(entry->sas, -1, sa);
		this->sas->put(this->sas, sa, entry);
	}
	else
	{
		DBG1(DBG_KNL, "adding SA failed, a different SA with reqid %u exists",
			 reqid);
		status = FAILED;
	}
	this->mutex->unlock(this->mutex);

	return status;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_kernel_wfp_ipsec_t *this, u_int32_t spi, u_int8_t protocol,
	u_int16_t cpi, host_t *src, host_t *dst, host_t *new_src, host_t *new_dst,
	bool encap, bool new_encap, mark_t mark)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, mark_t mark, u_int64_t *bytes,
	u_int64_t *packets, time_t *time)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int16_t cpi, mark_t mark)
{
	status_t status = NOT_FOUND;
	entry_t *entry;
	host_t *local, *remote;
	enumerator_t *enumerator;
	sa_entry_t *sa, key = {
		.dst = dst,
		.spi = spi,
	};

	this->mutex->lock(this->mutex);

	entry = this->sas->get(this->sas, &key);
	if (entry)
	{
		enumerator = array_create_enumerator(entry->sas);
		while (enumerator->enumerate(enumerator, &sa))
		{
			if (sa->inbound)
			{
				local = dst;
				remote = src;
			}
			else
			{
				local = src;
				remote = dst;
			}
			if (sa->spi == spi && entry->protocol == protocol &&
				local->ip_equals(local, entry->local) &&
				remote->ip_equals(remote, entry->remote))
			{
				array_remove_at(entry->sas, enumerator);
				this->sas->remove(this->sas, sa);
				/* TODO: uninstall SA from kernel */
				sa_entry_destroy(sa);
				status = SUCCESS;
				break;
			}
		}
		enumerator->destroy(enumerator);

		if (!array_count(entry->sas) && !array_count(entry->sps))
		{
			entry = this->entries->remove(this->entries,
										  (void*)(uintptr_t)entry->reqid);
			if (entry)
			{
				entry_destroy(entry);
			}
		}
	}

	this->mutex->unlock(this->mutex);

	return status;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
	private_kernel_wfp_ipsec_t *this)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_kernel_wfp_ipsec_t *this, host_t *src, host_t *dst,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, policy_type_t type, ipsec_sa_cfg_t *sa, mark_t mark,
	policy_priority_t priority)
{
	status_t status = SUCCESS;
	host_t *local, *remote;
	entry_t *entry;
	sp_entry_t *sp;

	if (direction == POLICY_FWD || priority != POLICY_PRIORITY_DEFAULT)
	{
		return SUCCESS;
	}

	if (direction == POLICY_IN)
	{
		local = dst;
		remote = src;
	}
	else
	{
		local = src;
		remote = dst;
	}

	this->mutex->lock(this->mutex);
	entry = get_or_create_entry(this, sa->reqid, local, remote,
								sa->esp.use ? IPPROTO_ESP : IPPROTO_AH,
								sa->mode, FALSE);
	if (entry)
	{
		INIT(sp,
			.src = src_ts->clone(src_ts),
			.dst = dst_ts->clone(dst_ts),
			.direction = direction,
		);
		array_insert(entry->sps, -1, sp);
	}
	else
	{
		DBG1(DBG_KNL, "adding SP failed, a different SP with reqid %u exists",
			 sa->reqid);
		status = FAILED;
	}
	this->mutex->unlock(this->mutex);

	return status;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_kernel_wfp_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, mark_t mark,
	time_t *use_time)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_kernel_wfp_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, u_int32_t reqid,
	mark_t mark, policy_priority_t priority)
{
	status_t status = NOT_FOUND;
	entry_t *entry;
	sp_entry_t *sp;
	enumerator_t *enumerator;

	this->mutex->lock(this->mutex);

	entry = this->entries->get(this->entries, (void*)(uintptr_t)reqid);
	if (entry)
	{
		enumerator = array_create_enumerator(entry->sps);
		while (enumerator->enumerate(enumerator, &sp))
		{
			if (sp->direction == direction &&
				src_ts->equals(src_ts, sp->src) &&
				dst_ts->equals(dst_ts, sp->dst))
			{
				array_remove_at(entry->sps, enumerator);
				/* TODO: uninstall SP from kernel */
				sp_entry_destroy(sp);
				status = SUCCESS;
				break;
			}
		}
		enumerator->destroy(enumerator);

		if (!array_count(entry->sas) && !array_count(entry->sps))
		{
			entry = this->entries->remove(this->entries,
										  (void*)(uintptr_t)reqid);
			if (entry)
			{
				entry_destroy(entry);
			}
		}
	}

	this->mutex->unlock(this->mutex);

	return status;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_kernel_wfp_ipsec_t *this)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_kernel_wfp_ipsec_t *this, int fd, int family)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_kernel_wfp_ipsec_t *this, int fd, int family, u_int16_t port)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, destroy, void,
	private_kernel_wfp_ipsec_t *this)
{
	if (this->handle)
	{
		FwpmEngineClose0(this->handle);
	}
	this->entries->destroy(this->entries);
	this->sas->destroy(this->sas);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * Described in header.
 */
kernel_wfp_ipsec_t *kernel_wfp_ipsec_create()
{
	private_kernel_wfp_ipsec_t *this;
	DWORD res;
	FWPM_SESSION0 session = {
		.displayData = {
			.name = L"charon",
			.description = L"strongSwan IKE kernel-wfp backend",
		},
	};

	INIT(this,
		.public = {
			.interface = {
				.get_features = _get_features,
				.get_spi = _get_spi,
				.get_cpi = _get_cpi,
				.add_sa  = _add_sa,
				.update_sa = _update_sa,
				.query_sa = _query_sa,
				.del_sa = _del_sa,
				.flush_sas = _flush_sas,
				.add_policy = _add_policy,
				.query_policy = _query_policy,
				.del_policy = _del_policy,
				.flush_policies = _flush_policies,
				.bypass_socket = _bypass_socket,
				.enable_udp_decap = _enable_udp_decap,
				.destroy = _destroy,
			},
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.entries = hashtable_create(hashtable_hash_ptr,
									hashtable_equals_ptr, 4),
		.sas = hashtable_create((void*)hash_sa, (void*)equals_sa, 4),
	);

	res = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session,
						  &this->handle);
	if (res != ERROR_SUCCESS)
	{
		DBG1(DBG_KNL, "opening WFP engine failed: 0x%08x", res);
		destroy(this);
		return NULL;
	}

	return &this->public;
}
