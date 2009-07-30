/*
 * Copyright (C) 2008 Tobias Brunner
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

#include "kernel_interface.h"

#include <pthread.h>

#include <daemon.h>

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
	 * ipsec interface
	 */
	kernel_ipsec_t *ipsec;
	
	/**
	 * network interface
	 */
	kernel_net_t *net;
};

/**
 * Implementation of kernel_interface_t.get_spi
 */
static status_t get_spi(private_kernel_interface_t *this, host_t *src, host_t *dst, 
				 protocol_id_t protocol, u_int32_t reqid, u_int32_t *spi)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->get_spi(this->ipsec, src, dst, protocol, reqid, spi);
}

/**
 * Implementation of kernel_interface_t.get_cpi
 */
static status_t get_cpi(private_kernel_interface_t *this, host_t *src, host_t *dst, 
					u_int32_t reqid, u_int16_t *cpi)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->get_cpi(this->ipsec, src, dst, reqid, cpi);
}

/**
 * Implementation of kernel_interface_t.add_sa
 */
static status_t add_sa(private_kernel_interface_t *this, host_t *src, host_t *dst,
				u_int32_t spi, protocol_id_t protocol, u_int32_t reqid,
				u_int64_t expire_soft, u_int64_t expire_hard,
				u_int16_t enc_alg, chunk_t enc_key,
				u_int16_t int_alg, chunk_t int_key,
				ipsec_mode_t mode, u_int16_t ipcomp, u_int16_t cpi, bool encap,
				bool inbound)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->add_sa(this->ipsec, src, dst, spi, protocol, reqid,
			expire_soft, expire_hard, enc_alg, enc_key, int_alg, int_key,
			mode, ipcomp, cpi, encap, inbound);
}

/**
 * Implementation of kernel_interface_t.update_sa
 */
static status_t update_sa(private_kernel_interface_t *this, u_int32_t spi,
				   protocol_id_t protocol, u_int16_t cpi, host_t *src, host_t *dst, 
				   host_t *new_src, host_t *new_dst, bool encap, bool new_encap)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->update_sa(this->ipsec, spi, protocol, cpi, src, dst,
			new_src, new_dst, encap, new_encap);
}

/**
 * Implementation of kernel_interface_t.query_sa
 */
static status_t query_sa(private_kernel_interface_t *this, host_t *src, host_t *dst,
						 u_int32_t spi, protocol_id_t protocol, u_int64_t *bytes)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->query_sa(this->ipsec, src, dst, spi, protocol, bytes);
}

/**
 * Implementation of kernel_interface_t.del_sa
 */
static status_t del_sa(private_kernel_interface_t *this, host_t *src, host_t *dst,
				u_int32_t spi, protocol_id_t protocol, u_int16_t cpi)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->del_sa(this->ipsec, src, dst, spi, protocol, cpi);
}

/**
 * Implementation of kernel_interface_t.add_policy
 */
static status_t add_policy(private_kernel_interface_t *this, host_t *src, host_t *dst,
					traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
					policy_dir_t direction, u_int32_t spi, protocol_id_t protocol,
					u_int32_t reqid, ipsec_mode_t mode, u_int16_t ipcomp, u_int16_t cpi,
					bool routed)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->add_policy(this->ipsec, src, dst, src_ts, dst_ts,
			direction, spi, protocol, reqid, mode, ipcomp, cpi, routed);
}

/**
 * Implementation of kernel_interface_t.query_policy
 */
static status_t query_policy(private_kernel_interface_t *this,
					  traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
					  policy_dir_t direction, u_int32_t *use_time)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->query_policy(this->ipsec, src_ts, dst_ts, direction, use_time);
}

/**
 * Implementation of kernel_interface_t.del_policy
 */
static status_t del_policy(private_kernel_interface_t *this,
					traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
					policy_dir_t direction, bool unrouted)
{
	if (!this->ipsec)
	{
		return NOT_SUPPORTED;
	}
	return this->ipsec->del_policy(this->ipsec, src_ts, dst_ts, direction, unrouted);
}

/**
 * Implementation of kernel_interface_t.get_source_addr
 */
static host_t *get_source_addr(private_kernel_interface_t *this,
							   host_t *dest, host_t *src)
{
	if (!this->net)
	{
		return NULL;
	}
	return this->net->get_source_addr(this->net, dest, src);
}

/**
 * Implementation of kernel_interface_t.get_nexthop
 */
static host_t *get_nexthop(private_kernel_interface_t *this, host_t *dest)
{
	if (!this->net)
	{
		return NULL;
	}
	return this->net->get_nexthop(this->net, dest);
}

/**
 * Implementation of kernel_interface_t.get_interface
 */
static char* get_interface(private_kernel_interface_t *this, host_t *host)
{
	if (!this->net)
	{
		return NULL;
	}
	return this->net->get_interface(this->net, host);
}

/**
 * Implementation of kernel_interface_t.create_address_enumerator
 */
static enumerator_t *create_address_enumerator(private_kernel_interface_t *this,
		bool include_down_ifaces, bool include_virtual_ips)
{
	if (!this->net)
	{
		return enumerator_create_empty();
	}
	return this->net->create_address_enumerator(this->net, include_down_ifaces,
			include_virtual_ips);
}

/**
 * Implementation of kernel_interface_t.add_ip
 */
static status_t add_ip(private_kernel_interface_t *this, host_t *virtual_ip,
				host_t *iface_ip)
{
	if (!this->net)
	{
		return NOT_SUPPORTED;
	}
	return this->net->add_ip(this->net, virtual_ip, iface_ip);
}

/**
 * Implementation of kernel_interface_t.del_ip
 */
static status_t del_ip(private_kernel_interface_t *this, host_t *virtual_ip)
{
	if (!this->net)
	{
		return NOT_SUPPORTED;
	}
	return this->net->del_ip(this->net, virtual_ip);
}

/**
 * Implementation of kernel_interface_t.add_route
 */
static status_t add_route(private_kernel_interface_t *this, chunk_t dst_net,
		u_int8_t prefixlen, host_t *gateway, host_t *src_ip, char *if_name)
{
	if (!this->net)
	{
		return NOT_SUPPORTED;
	}
	return this->net->add_route(this->net, dst_net, prefixlen, gateway, src_ip,
			if_name);
}

/**
 * Implementation of kernel_interface_t.del_route
 */
static status_t del_route(private_kernel_interface_t *this, chunk_t dst_net,
		u_int8_t prefixlen, host_t *gateway, host_t *src_ip, char *if_name)
{
	if (!this->net)
	{
		return NOT_SUPPORTED;
	}
	return this->net->del_route(this->net, dst_net, prefixlen, gateway, src_ip,
			if_name);
}


/**
 * Implementation of kernel_interface_t.get_address_by_ts
 */
static status_t get_address_by_ts(private_kernel_interface_t *this,
								  traffic_selector_t *ts, host_t **ip)
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
		DBG1(DBG_KNL, "no local address found in traffic selector %R", ts);
		return FAILED;
	}
	
	DBG2(DBG_KNL, "using host %H", *ip);
	return SUCCESS;
}


/**
 * Implementation of kernel_interface_t.add_ipsec_interface.
 */
static void add_ipsec_interface(private_kernel_interface_t *this,
		kernel_ipsec_constructor_t constructor)
{
	if (!this->ipsec)
	{
		this->ipsec = constructor();
	}
}

/**
 * Implementation of kernel_interface_t.remove_ipsec_interface.
 */
static void remove_ipsec_interface(private_kernel_interface_t *this,
		kernel_ipsec_constructor_t constructor)
{
	/* TODO: replace if interface currently in use */
}

/**
 * Implementation of kernel_interface_t.add_net_interface.
 */
static void add_net_interface(private_kernel_interface_t *this,
		kernel_net_constructor_t constructor)
{
	if (!this->net)
	{
		this->net = constructor();
	}
}

/**
 * Implementation of kernel_interface_t.remove_net_interface.
 */
static void remove_net_interface(private_kernel_interface_t *this,
		kernel_net_constructor_t constructor)
{
	/* TODO: replace if interface currently in use */
}

/**
 * Implementation of kernel_interface_t.destroy.
 */
static void destroy(private_kernel_interface_t *this)
{
	DESTROY_IF(this->ipsec);
	DESTROY_IF(this->net);
	free(this);
}

/*
 * Described in header-file
 */
kernel_interface_t *kernel_interface_create()
{
	private_kernel_interface_t *this = malloc_thing(private_kernel_interface_t);
	
	this->public.get_spi = (status_t(*)(kernel_interface_t*,host_t*,host_t*,protocol_id_t,u_int32_t,u_int32_t*))get_spi;
	this->public.get_cpi = (status_t(*)(kernel_interface_t*,host_t*,host_t*,u_int32_t,u_int16_t*))get_cpi;
	this->public.add_sa  = (status_t(*)(kernel_interface_t *,host_t*,host_t*,u_int32_t,protocol_id_t,u_int32_t,u_int64_t,u_int64_t,u_int16_t,chunk_t,u_int16_t,chunk_t,ipsec_mode_t,u_int16_t,u_int16_t,bool,bool))add_sa;
	this->public.update_sa = (status_t(*)(kernel_interface_t*,u_int32_t,protocol_id_t,u_int16_t,host_t*,host_t*,host_t*,host_t*,bool,bool))update_sa;
	this->public.query_sa = (status_t(*)(kernel_interface_t*,host_t*,host_t*,u_int32_t,protocol_id_t,u_int64_t*))query_sa;
	this->public.del_sa = (status_t(*)(kernel_interface_t*,host_t*,host_t*,u_int32_t,protocol_id_t,u_int16_t))del_sa;
	this->public.add_policy = (status_t(*)(kernel_interface_t*,host_t*,host_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,u_int32_t,protocol_id_t,u_int32_t,ipsec_mode_t,u_int16_t,u_int16_t,bool))add_policy;
	this->public.query_policy = (status_t(*)(kernel_interface_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,u_int32_t*))query_policy;
	this->public.del_policy = (status_t(*)(kernel_interface_t*,traffic_selector_t*,traffic_selector_t*,policy_dir_t,bool))del_policy;
	
	this->public.get_source_addr = (host_t*(*)(kernel_interface_t*, host_t *dest, host_t *src))get_source_addr;
	this->public.get_nexthop = (host_t*(*)(kernel_interface_t*, host_t *dest))get_nexthop;
	this->public.get_interface = (char*(*)(kernel_interface_t*,host_t*))get_interface;
	this->public.create_address_enumerator = (enumerator_t*(*)(kernel_interface_t*,bool,bool))create_address_enumerator;
	this->public.add_ip = (status_t(*)(kernel_interface_t*,host_t*,host_t*)) add_ip;
	this->public.del_ip = (status_t(*)(kernel_interface_t*,host_t*)) del_ip;
	this->public.add_route = (status_t(*)(kernel_interface_t*,chunk_t,u_int8_t,host_t*,host_t*,char*)) add_route;
	this->public.del_route = (status_t(*)(kernel_interface_t*,chunk_t,u_int8_t,host_t*,host_t*,char*)) del_route;
	
	this->public.get_address_by_ts = (status_t(*)(kernel_interface_t*,traffic_selector_t*,host_t**))get_address_by_ts;
	
	this->public.add_ipsec_interface = (void(*)(kernel_interface_t*, kernel_ipsec_constructor_t))add_ipsec_interface;
	this->public.remove_ipsec_interface = (void(*)(kernel_interface_t*, kernel_ipsec_constructor_t))remove_ipsec_interface;
	this->public.add_net_interface = (void(*)(kernel_interface_t*, kernel_net_constructor_t))add_net_interface;
	this->public.remove_net_interface = (void(*)(kernel_interface_t*, kernel_net_constructor_t))remove_net_interface;
	
	this->public.destroy = (void (*)(kernel_interface_t*))destroy;
	
	this->ipsec = NULL;
	this->net = NULL;
	
	return &this->public;
}
