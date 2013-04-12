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

#include "kernel_utun_ipsec.h"

#include <hydra.h>
#include <utils/debug.h>
#include <threading/mutex.h>

typedef struct private_kernel_utun_ipsec_t private_kernel_utun_ipsec_t;

/**
 * Private variables and functions of kernel_utun class.
 */
struct private_kernel_utun_ipsec_t {

	/**
	 * Public part of the kernel_utun_t object
	 */
	kernel_utun_ipsec_t public;

	/**
	 * Mutex to access shared objects
	 */
	mutex_t *mutex;

	/**
	 * Next SPI to allocate
	 */
	u_int32_t spi;
};

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
	private_kernel_utun_ipsec_t *this)
{
	return 0;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_kernel_utun_ipsec_t *this, host_t *src, host_t *dst,
	u_int8_t protocol, u_int32_t reqid, u_int32_t *spi)
{
	this->mutex->lock(this->mutex);
	*spi = this->spi++;
	this->mutex->unlock(this->mutex);

	return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_kernel_utun_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t reqid, u_int16_t *cpi)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_kernel_utun_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int32_t reqid, mark_t mark,
	u_int32_t tfc, lifetime_cfg_t *lifetime, u_int16_t enc_alg, chunk_t enc_key,
	u_int16_t int_alg, chunk_t int_key, ipsec_mode_t mode, u_int16_t ipcomp,
	u_int16_t cpi, bool encap, bool esn, bool inbound,
	traffic_selector_t* src_ts, traffic_selector_t* dst_ts)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_kernel_utun_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, mark_t mark,
	u_int64_t *bytes, u_int64_t *packets)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_kernel_utun_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int16_t cpi, mark_t mark)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_kernel_utun_ipsec_t *this, u_int32_t spi, u_int8_t protocol,
	u_int16_t cpi, host_t *src, host_t *dst, host_t *new_src, host_t *new_dst,
	bool old_encap, bool new_encap, mark_t mark)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
	private_kernel_utun_ipsec_t *this)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_kernel_utun_ipsec_t *this, host_t *src, host_t *dst,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, policy_type_t type, ipsec_sa_cfg_t *sa,
	mark_t mark, policy_priority_t priority)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_kernel_utun_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, mark_t mark,
	u_int32_t *use_time)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_kernel_utun_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, u_int32_t reqid,
	mark_t mark, policy_priority_t prio)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_kernel_utun_ipsec_t *this)
{
	return FAILED;
}


METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_kernel_utun_ipsec_t *this, int fd, int family)
{
	return FALSE;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_kernel_utun_ipsec_t *this, int fd, int family, u_int16_t port)
{
	return FALSE;
}

METHOD(kernel_ipsec_t, destroy, void,
	private_kernel_utun_ipsec_t *this)
{
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * Described in header.
 */
kernel_utun_ipsec_t *kernel_utun_ipsec_create()
{
	private_kernel_utun_ipsec_t *this;

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
		/* initialize to "charon-style" SPIs with a leading "c" */
		.spi = 0xc0000000,
	);
	return &this->public;
}
