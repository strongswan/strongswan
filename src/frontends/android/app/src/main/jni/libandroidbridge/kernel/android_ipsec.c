/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.  *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "android_ipsec.h"
#include "../charonservice.h"

#include <utils/debug.h>
#include <library.h>
#include <hydra.h>
#include <ipsec.h>

typedef struct private_kernel_android_ipsec_t private_kernel_android_ipsec_t;

struct private_kernel_android_ipsec_t {

	/**
	 * Public kernel interface
	 */
	kernel_android_ipsec_t public;

	/**
	 * Listener for lifetime expire events
	 */
	ipsec_event_listener_t ipsec_listener;
};

/**
 * Callback registrered with libipsec.
 */
static void expire(u_int8_t protocol, u_int32_t spi, host_t *dst, bool hard)
{
	hydra->kernel_interface->expire(hydra->kernel_interface, protocol,
									spi, dst, hard);
}

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_kernel_android_ipsec_t *this, host_t *src, host_t *dst,
	u_int8_t protocol, u_int32_t *spi)
{
	return ipsec->sas->get_spi(ipsec->sas, src, dst, protocol, spi);
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_kernel_android_ipsec_t *this, host_t *src, host_t *dst,
	u_int16_t *cpi)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_kernel_android_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int32_t reqid, mark_t mark,
	u_int32_t tfc, lifetime_cfg_t *lifetime, u_int16_t enc_alg, chunk_t enc_key,
	u_int16_t int_alg, chunk_t int_key, ipsec_mode_t mode,
	u_int16_t ipcomp, u_int16_t cpi, u_int32_t replay_window,
	bool initiator, bool encap, bool esn, bool inbound, bool update,
	linked_list_t *src_ts, linked_list_t *dst_ts)
{
	return ipsec->sas->add_sa(ipsec->sas, src, dst, spi, protocol, reqid, mark,
							  tfc, lifetime, enc_alg, enc_key, int_alg, int_key,
							  mode, ipcomp, cpi, initiator, encap, esn,
							  inbound, update);
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_kernel_android_ipsec_t *this, u_int32_t spi, u_int8_t protocol,
	u_int16_t cpi, host_t *src, host_t *dst, host_t *new_src, host_t *new_dst,
	bool encap, bool new_encap, mark_t mark)
{
	return ipsec->sas->update_sa(ipsec->sas, spi, protocol, cpi, src, dst,
								 new_src, new_dst, encap, new_encap, mark);
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_kernel_android_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, mark_t mark,
	u_int64_t *bytes, u_int64_t *packets, time_t *time)
{
	return ipsec->sas->query_sa(ipsec->sas, src, dst, spi, protocol, mark,
								bytes, packets, time);
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_kernel_android_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int16_t cpi, mark_t mark)
{
	return ipsec->sas->del_sa(ipsec->sas, src, dst, spi, protocol, cpi, mark);
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
	private_kernel_android_ipsec_t *this)
{
	return ipsec->sas->flush_sas(ipsec->sas);
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_kernel_android_ipsec_t *this, host_t *src, host_t *dst,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, policy_type_t type, ipsec_sa_cfg_t *sa, mark_t mark,
	policy_priority_t priority)
{
	return ipsec->policies->add_policy(ipsec->policies, src, dst, src_ts,
									   dst_ts, direction, type, sa, mark,
									   priority);
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_kernel_android_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, mark_t mark,
	time_t *use_time)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_kernel_android_ipsec_t *this, host_t *src, host_t *dst,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, policy_type_t type, ipsec_sa_cfg_t *sa,
	mark_t mark, policy_priority_t priority)
{
	return ipsec->policies->del_policy(ipsec->policies, src, dst, src_ts,
									   dst_ts,  direction, type, sa, mark,
									   priority);
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_kernel_android_ipsec_t *this)
{
	ipsec->policies->flush_policies(ipsec->policies);
	return SUCCESS;
}

METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_kernel_android_ipsec_t *this, int fd, int family)
{
	return charonservice->bypass_socket(charonservice, fd, family);
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_kernel_android_ipsec_t *this, int fd, int family, u_int16_t port)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, destroy, void,
	private_kernel_android_ipsec_t *this)
{
	ipsec->events->unregister_listener(ipsec->events, &this->ipsec_listener);
	free(this);
}

/*
 * Described in header.
 */
kernel_android_ipsec_t *kernel_android_ipsec_create()
{
	private_kernel_android_ipsec_t *this;

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
		.ipsec_listener = {
			.expire = expire,
		},
	);

	ipsec->events->register_listener(ipsec->events, &this->ipsec_listener);

	return &this->public;
}
