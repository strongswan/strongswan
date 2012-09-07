/*
 * Copyright (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
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

#include <utils/debug.h>
#include <plugins/kernel_netlink/kernel_netlink_ipsec.h>

#include "tkm_kernel_ipsec.h"

typedef struct private_tkm_kernel_ipsec_t private_tkm_kernel_ipsec_t;

/**
 * Private variables and functions of TKM kernel ipsec instance.
 */
struct private_tkm_kernel_ipsec_t {

	/**
	 * Public tkm_kernel_ipsec interface.
	 */
	tkm_kernel_ipsec_t public;

	/**
	 * Kernel interface proxy (will be removed).
	 */
	kernel_netlink_ipsec_t *proxy;

};

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_tkm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	u_int8_t protocol, u_int32_t reqid, u_int32_t *spi)
{
	DBG1(DBG_KNL, "getting SPI for reqid {%u}", reqid);
	return this->proxy->interface.get_spi(&this->proxy->interface, src, dst,
										  protocol, reqid, spi);
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_tkm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t reqid, u_int16_t *cpi)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_tkm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int32_t reqid, mark_t mark,
	u_int32_t tfc, lifetime_cfg_t *lifetime, u_int16_t enc_alg, chunk_t enc_key,
	u_int16_t int_alg, chunk_t int_key, ipsec_mode_t mode, u_int16_t ipcomp,
	u_int16_t cpi, bool encap, bool esn, bool inbound,
	traffic_selector_t* src_ts, traffic_selector_t* dst_ts)
{
	DBG1(DBG_KNL, "adding child SA with SPI %.8x and reqid {%u}", ntohl(spi),
		 reqid);
	return this->proxy->interface.add_sa(&this->proxy->interface, src, dst, spi,
										 protocol, reqid, mark, tfc, lifetime,
										 enc_alg, enc_key, int_alg, int_key,
										 mode, ipcomp, cpi, encap, esn, inbound,
										 src_ts, dst_ts);
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_tkm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, mark_t mark, u_int64_t *bytes,
	u_int64_t *packets)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_tkm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int16_t cpi, mark_t mark)
{
	DBG1(DBG_KNL, "deleting child SA with SPI %.8x", ntohl(spi));
	return this->proxy->interface.del_sa(&this->proxy->interface, src, dst, spi,
										 protocol, cpi, mark);
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_tkm_kernel_ipsec_t *this, u_int32_t spi, u_int8_t protocol,
	u_int16_t cpi, host_t *src, host_t *dst, host_t *new_src, host_t *new_dst,
	bool old_encap, bool new_encap, mark_t mark)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
	private_tkm_kernel_ipsec_t *this)
{
	DBG1(DBG_KNL, "flushing child SA entries");
	return this->proxy->interface.flush_sas(&this->proxy->interface);
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_tkm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, policy_type_t type, ipsec_sa_cfg_t *sa,
	mark_t mark, policy_priority_t priority)
{
	return this->proxy->interface.add_policy(&this->proxy->interface, src, dst,
											 src_ts, dst_ts, direction, type,
											 sa, mark, priority);
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_tkm_kernel_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, mark_t mark,
	u_int32_t *use_time)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_tkm_kernel_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, u_int32_t reqid,
	mark_t mark, policy_priority_t prio)
{
	return this->proxy->interface.del_policy(&this->proxy->interface, src_ts,
											 dst_ts, direction, reqid, mark,
											 prio);
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_tkm_kernel_ipsec_t *this)
{
	return this->proxy->interface.flush_policies(&this->proxy->interface);
}


METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_tkm_kernel_ipsec_t *this, int fd, int family)
{
	return this->proxy->interface.bypass_socket(&this->proxy->interface, fd,
												family);
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_tkm_kernel_ipsec_t *this, int fd, int family, u_int16_t port)
{
	return this->proxy->interface.enable_udp_decap(&this->proxy->interface, fd,
												   family, port);
}

METHOD(kernel_ipsec_t, destroy, void,
	private_tkm_kernel_ipsec_t *this)
{
	this->proxy->interface.destroy(&this->proxy->interface);
	free(this);
}

/*
 * Described in header.
 */
tkm_kernel_ipsec_t *tkm_kernel_ipsec_create()
{
	private_tkm_kernel_ipsec_t *this;

	INIT(this,
		.public = {
			.interface = {
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
		.proxy = kernel_netlink_ipsec_create(),
	);

	if (!this->proxy)
	{
		free(this);
		return NULL;
	}

	return &this->public;
}
