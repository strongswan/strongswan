/*
 * Copyright (C) 2008-2011 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "kernel_interface.h"

#include <debug.h>
#include <threading/mutex.h>
#include <utils/linked_list.h>

typedef struct private_kernel_interface_t private_kernel_interface_t;

/**
 * Private data of a kernel_interface_t object.
 */
struct private_kernel_interface_t {

	/**
	 * Public part of kernel_interface_t object.
	 */
	kernel_interface_t public;

	/**
	 * Registered IPsec constructor
	 */
	kernel_ipsec_constructor_t ipsec_constructor;

	/**
	 * Registered net constructor
	 */
	kernel_net_constructor_t net_constructor;

	/**
	 * ipsec interface
	 */
	kernel_ipsec_t *ipsec;

	/**
	 * network interface
	 */
	kernel_net_t *net;

	/**
	 * mutex for listeners
	 */
	mutex_t *mutex;

	/**
	 * list of registered listeners
	 */
	linked_list_t *listeners;
};

METHOD(kernel_interface_t, get_spi, status_t,
	private_kernel_interface_t *this, host_t *src, host_t *dst,
	u_int8_t protocol, u_int32_t reqid, u_int32_t *spi)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->get_spi(this->ipsec, src, dst, protocol, reqid, spi);
}

METHOD(kernel_interface_t, get_cpi, status_t,
	private_kernel_interface_t *this, host_t *src, host_t *dst,
	u_int32_t reqid, u_int16_t *cpi)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->get_cpi(this->ipsec, src, dst, reqid, cpi);
}

METHOD(kernel_interface_t, add_sa, status_t,
	private_kernel_interface_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int32_t reqid, mark_t mark,
	u_int32_t tfc, lifetime_cfg_t *lifetime, u_int16_t enc_alg, chunk_t enc_key,
	u_int16_t int_alg, chunk_t int_key,	ipsec_mode_t mode, u_int16_t ipcomp,
	u_int16_t cpi, bool encap, bool esn, bool inbound,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->add_sa(this->ipsec, src, dst, spi, protocol, reqid,
			mark, tfc, lifetime, enc_alg, enc_key, int_alg, int_key, mode,
			ipcomp, cpi, encap, esn, inbound, src_ts, dst_ts);
}

METHOD(kernel_interface_t, update_sa, status_t,
	private_kernel_interface_t *this, u_int32_t spi, u_int8_t protocol,
	u_int16_t cpi, host_t *src, host_t *dst, host_t *new_src, host_t *new_dst,
	bool encap, bool new_encap, mark_t mark)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->update_sa(this->ipsec, spi, protocol, cpi, src, dst,
								  new_src, new_dst, encap, new_encap, mark);
}

METHOD(kernel_interface_t, query_sa, status_t,
	private_kernel_interface_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, mark_t mark, u_int64_t *bytes)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->query_sa(this->ipsec, src, dst, spi, protocol, mark, bytes);
}

METHOD(kernel_interface_t, del_sa, status_t,
	private_kernel_interface_t *this, host_t *src, host_t *dst, u_int32_t spi,
	u_int8_t protocol, u_int16_t cpi, mark_t mark)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->del_sa(this->ipsec, src, dst, spi, protocol, cpi, mark);
}

METHOD(kernel_interface_t, flush_sas, status_t,
	private_kernel_interface_t *this)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->flush_sas(this->ipsec);
}

METHOD(kernel_interface_t, add_policy, status_t,
	private_kernel_interface_t *this, host_t *src, host_t *dst,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, policy_type_t type, ipsec_sa_cfg_t *sa,
	mark_t mark, policy_priority_t priority)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->add_policy(this->ipsec, src, dst, src_ts, dst_ts,
								   direction, type, sa, mark, priority);
}

METHOD(kernel_interface_t, query_policy, status_t,
	private_kernel_interface_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, mark_t mark,
	u_int32_t *use_time)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->query_policy(this->ipsec, src_ts, dst_ts,
									 direction, mark, use_time);
}

METHOD(kernel_interface_t, del_policy, status_t,
	private_kernel_interface_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, u_int32_t reqid,
	mark_t mark, policy_priority_t priority)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->del_policy(this->ipsec, src_ts, dst_ts,
								   direction, reqid, mark, priority);
}

METHOD(kernel_interface_t, flush_policies, status_t,
	private_kernel_interface_t *this)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->flush_policies(this->ipsec);
}

METHOD(kernel_interface_t, get_source_addr, host_t*,
	private_kernel_interface_t *this, host_t *dest, host_t *src)
{
	if (!this->net)
	{
		return NULL;
	}
	return this->net->get_source_addr(this->net, dest, src);
}

METHOD(kernel_interface_t, get_nexthop, host_t*,
	private_kernel_interface_t *this, host_t *dest)
{
	if (!this->net)
	{
		return NULL;
	}
	return this->net->get_nexthop(this->net, dest);
}

METHOD(kernel_interface_t, get_interface, char*,
	private_kernel_interface_t *this, host_t *host)
{
	if (!this->net)
	{
		return NULL;
	}
	return this->net->get_interface(this->net, host);
}

METHOD(kernel_interface_t, create_address_enumerator, enumerator_t*,
	private_kernel_interface_t *this, bool include_down_ifaces,
	bool include_virtual_ips)
{
	if (!this->net)
	{
		return enumerator_create_empty();
	}
	return this->net->create_address_enumerator(this->net, include_down_ifaces,
												include_virtual_ips);
}

METHOD(kernel_interface_t, add_ip, status_t,
	private_kernel_interface_t *this, host_t *virtual_ip, host_t *iface_ip)
{
	if (!this->net)
	{
		return NOT_SUPPORTED;
	}
	return this->net->add_ip(this->net, virtual_ip, iface_ip);
}

METHOD(kernel_interface_t, del_ip, status_t,
	private_kernel_interface_t *this, host_t *virtual_ip)
{
	if (!this->net)
	{
		return NOT_SUPPORTED;
	}
	return this->net->del_ip(this->net, virtual_ip);
}

METHOD(kernel_interface_t, add_route, status_t,
	private_kernel_interface_t *this, chunk_t dst_net,
	u_int8_t prefixlen, host_t *gateway, host_t *src_ip, char *if_name)
{
	if (!this->net)
	{
		return NOT_SUPPORTED;
	}
	return this->net->add_route(this->net, dst_net, prefixlen, gateway,
								src_ip, if_name);
}

METHOD(kernel_interface_t, del_route, status_t,
	private_kernel_interface_t *this, chunk_t dst_net,
	u_int8_t prefixlen, host_t *gateway, host_t *src_ip, char *if_name)
{
	if (!this->net)
	{
		return NOT_SUPPORTED;
	}
	return this->net->del_route(this->net, dst_net, prefixlen, gateway,
								src_ip, if_name);
}

METHOD(kernel_interface_t, bypass_socket, bool,
	private_kernel_interface_t *this, int fd, int family)
{
	if (!this->ipsec)
	{
		return FALSE;
	}
	return this->ipsec->bypass_socket(this->ipsec, fd, family);
}

METHOD(kernel_interface_t, get_address_by_ts, status_t,
	private_kernel_interface_t *this, traffic_selector_t *ts, host_t **ip)
{
	enumerator_t *addrs;
	host_t *host;
	int family;
	bool found = FALSE;

	DBG2(DBG_KNL, "getting a local address in traffic selector %R", ts);

	/* if we have a family which includes localhost, we do not
	 * search for an IP, we use the default */
	family = ts->get_type(ts) == TS_IPV4_ADDR_RANGE ? AF_INET : AF_INET6;

	if (family == AF_INET)
	{
		host = host_create_from_string("127.0.0.1", 0);
	}
	else
	{
		host = host_create_from_string("::1", 0);
	}

	if (ts->includes(ts, host))
	{
		*ip = host_create_any(family);
		host->destroy(host);
		DBG2(DBG_KNL, "using host %H", *ip);
		return SUCCESS;
	}
	host->destroy(host);

	addrs = create_address_enumerator(this, TRUE, TRUE);
	while (addrs->enumerate(addrs, (void**)&host))
	{
		if (ts->includes(ts, host))
		{
			found = TRUE;
			*ip = host->clone(host);
			break;
		}
	}
	addrs->destroy(addrs);

	if (!found)
	{
		DBG2(DBG_KNL, "no local address found in traffic selector %R", ts);
		return FAILED;
	}

	DBG2(DBG_KNL, "using host %H", *ip);
	return SUCCESS;
}


METHOD(kernel_interface_t, add_ipsec_interface, void,
	private_kernel_interface_t *this, kernel_ipsec_constructor_t constructor)
{
	if (!this->ipsec)
	{
		this->ipsec_constructor = constructor;
		this->ipsec = constructor();
	}
}

METHOD(kernel_interface_t, remove_ipsec_interface, void,
	private_kernel_interface_t *this, kernel_ipsec_constructor_t constructor)
{
	if (constructor == this->ipsec_constructor)
	{
		this->ipsec->destroy(this->ipsec);
		this->ipsec = NULL;
	}
}

METHOD(kernel_interface_t, add_net_interface, void,
	private_kernel_interface_t *this, kernel_net_constructor_t constructor)
{
	if (!this->net)
	{
		this->net_constructor = constructor;
		this->net = constructor();
	}
}

METHOD(kernel_interface_t, remove_net_interface, void,
	private_kernel_interface_t *this, kernel_net_constructor_t constructor)
{
	if (constructor == this->net_constructor)
	{
		this->net->destroy(this->net);
		this->net = NULL;
	}
}

METHOD(kernel_interface_t, add_listener, void,
	private_kernel_interface_t *this, kernel_listener_t *listener)
{
	this->mutex->lock(this->mutex);
	this->listeners->insert_last(this->listeners, listener);
	this->mutex->unlock(this->mutex);
}

METHOD(kernel_interface_t, remove_listener, void,
	private_kernel_interface_t *this, kernel_listener_t *listener)
{
	this->mutex->lock(this->mutex);
	this->listeners->remove(this->listeners, listener, NULL);
	this->mutex->unlock(this->mutex);
}

METHOD(kernel_interface_t, acquire, void,
	private_kernel_interface_t *this, u_int32_t reqid,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts)
{
	kernel_listener_t *listener;
	enumerator_t *enumerator;
	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &listener))
	{
		if (listener->acquire &&
			!listener->acquire(listener, reqid, src_ts, dst_ts))
		{
			this->listeners->remove_at(this->listeners, enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(kernel_interface_t, expire, void,
	private_kernel_interface_t *this, u_int32_t reqid, u_int8_t protocol,
	u_int32_t spi, bool hard)
{
	kernel_listener_t *listener;
	enumerator_t *enumerator;
	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &listener))
	{
		if (listener->expire &&
			!listener->expire(listener, reqid, protocol, spi, hard))
		{
			this->listeners->remove_at(this->listeners, enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(kernel_interface_t, mapping, void,
	private_kernel_interface_t *this, u_int32_t reqid, u_int32_t spi,
	host_t *remote)
{
	kernel_listener_t *listener;
	enumerator_t *enumerator;
	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &listener))
	{
		if (listener->mapping &&
			!listener->mapping(listener, reqid, spi, remote))
		{
			this->listeners->remove_at(this->listeners, enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

METHOD(kernel_interface_t, migrate, void,
	private_kernel_interface_t *this, u_int32_t reqid,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, host_t *local, host_t *remote)
{
	kernel_listener_t *listener;
	enumerator_t *enumerator;
	this->mutex->lock(this->mutex);
	enumerator = this->listeners->create_enumerator(this->listeners);
	while (enumerator->enumerate(enumerator, &listener))
	{
		if (listener->migrate &&
			!listener->migrate(listener, reqid, src_ts, dst_ts, direction,
							   local, remote))
		{
			this->listeners->remove_at(this->listeners, enumerator);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

static bool call_roam(kernel_listener_t *listener, bool *roam)
{
	return listener->roam && !listener->roam(listener, *roam);
}

METHOD(kernel_interface_t, roam, void,
	private_kernel_interface_t *this, bool address)
{
	this->mutex->lock(this->mutex);
	this->listeners->remove(this->listeners, &address, (void*)call_roam);
	this->mutex->unlock(this->mutex);
}

METHOD(kernel_interface_t, destroy, void,
	private_kernel_interface_t *this)
{
	DESTROY_IF(this->ipsec);
	DESTROY_IF(this->net);
	this->mutex->destroy(this->mutex);
	this->listeners->destroy(this->listeners);
	free(this);
}

/*
 * Described in header-file
 */
kernel_interface_t *kernel_interface_create()
{
	private_kernel_interface_t *this;

	INIT(this,
		.public = {
			.get_spi = _get_spi,
			.get_cpi = _get_cpi,
			.add_sa = _add_sa,
			.update_sa = _update_sa,
			.query_sa = _query_sa,
			.del_sa = _del_sa,
			.flush_sas = _flush_sas,
			.add_policy = _add_policy,
			.query_policy = _query_policy,
			.del_policy = _del_policy,
			.flush_policies = _flush_policies,
			.get_source_addr = _get_source_addr,
			.get_nexthop = _get_nexthop,
			.get_interface = _get_interface,
			.create_address_enumerator = _create_address_enumerator,
			.add_ip = _add_ip,
			.del_ip = _del_ip,
			.add_route = _add_route,
			.del_route = _del_route,
			.bypass_socket = _bypass_socket,

			.get_address_by_ts = _get_address_by_ts,
			.add_ipsec_interface = _add_ipsec_interface,
			.remove_ipsec_interface = _remove_ipsec_interface,
			.add_net_interface = _add_net_interface,
			.remove_net_interface = _remove_net_interface,

			.add_listener = _add_listener,
			.remove_listener = _remove_listener,
			.acquire = _acquire,
			.expire = _expire,
			.mapping = _mapping,
			.migrate = _migrate,
			.roam = _roam,
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.listeners = linked_list_create(),
	);

	return &this->public;
}

