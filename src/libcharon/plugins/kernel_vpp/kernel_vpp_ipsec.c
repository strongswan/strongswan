/*
 * Copyright (C) 2020 LabN Consulting, L.L.C.
 * Copyright (C) 2018 PANTHEON.tech.
 *
 * Copyright (C) 2006-2018 Tobias Brunner
 * Copyright (C) 2005-2009 Martin Willi
 * Copyright (C) 2008-2016 Andreas Steffen
 * Copyright (C) 2006-2007 Fabian Hartmann, Noah Heusser
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005 Jan Hutter
 * HSR Hochschule fuer Technik Rapperswil
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
/*
 * Copyright (C) 2018 Mellanox Technologies.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <assert.h>
#include <collections/hashtable.h>
#include <daemon.h>
#include <threading/mutex.h>
#include <utils/debug.h>
#include <vnet/ipsec/ipsec.h>

#include "kernel_vpp_ipsec.h"
#include "kernel_vpp_shared.h"

typedef struct private_kernel_vpp_ipsec_t private_kernel_vpp_ipsec_t;

/**
 * Private variables of kernel_vpp_ipsec class.
 */
struct private_kernel_vpp_ipsec_t {

	/**
	 * Public interface
	 */
	kernel_vpp_ipsec_t public;

	/**
	 * Next security association database entry ID to allocate
	 */
	refcount_t next_sad_id;

	/**
	 * Next security policy database entry ID to allocate
	 */
	refcount_t next_spd_id;

	/**
	 * Mutex to lock access to installed policies
	 */
	mutex_t *mutex;

	/**
	 * Hash table of instaled SA, as kernel_ipsec_sa_id_t => sa_t
	 */
	hashtable_t *sas;

	/**
	 * Hash table of security policy databases, as nterface => spd_t
	 */
	hashtable_t *spds;

	/**
	 * Linked list of installed routes
	 */
	linked_list_t *routes;

	/**
	 * Next SPI to allocate
	 */
	refcount_t nextspi;

	/**
	 * Mix value to distribute SPI allocation randomly
	 */
	uint32_t mixspi;

	/**
	 * Whether to install routes along policies
	 */
	bool install_routes;
};

/**
 * Security association entry
 */
typedef struct {
	/** VPP SA ID */
	uint32_t sa_id;
	/** Data required to add/delete SA to VPP */
	vl_api_ipsec_sad_entry_add_del_t *mp;
} sa_t;

/**
 * Security policy database
 */
typedef struct {
	/** VPP SPD ID */
	uint32_t spd_id;
	/** Networking interface ID restricting policy */
	uint32_t sw_if_index;
	/** Policy count for this SPD */
	refcount_t policy_num;
} spd_t;

/**
 * Installed route
 */
typedef struct {
	/** Name of the interface the route is bound to */
	char *if_name;
	/** Gateway of route */
	host_t *gateway;
	/** Destination network of route */
	host_t *dst_net;
	/** Prefix length of dst_net */
	uint8_t prefixlen;
	/** References for route */
	int refs;
} route_entry_t;

#define htonll(x)    \
	((1 == htonl(1)) \
		 ? (x)       \
		 : ((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))

CALLBACK(route_equals, bool, route_entry_t *a, va_list args)
{
	host_t *dst_net, *gateway;
	uint8_t *prefixlen;
	char *if_name;

	VA_ARGS_VGET(args, if_name, gateway, dst_net, prefixlen);

	return a->if_name && if_name && streq(a->if_name, if_name) &&
		   a->gateway->ip_equals(a->gateway, gateway) &&
		   a->dst_net->ip_equals(a->dst_net, dst_net) &&
		   a->prefixlen == *prefixlen;
}

/**
 * Clean up a route entry
 */
static void
route_destroy(route_entry_t *this)
{
	this->dst_net->destroy(this->dst_net);
	this->gateway->destroy(this->gateway);
	free(this->if_name);
	free(this);
}

/**
 * (Un)-install a single route
 */
static void
manage_route(private_kernel_vpp_ipsec_t *this, bool add,
			 traffic_selector_t *dst_ts, host_t *src, host_t *dst)
{
	host_t *dst_net = NULL, *gateway = NULL;
	uint8_t prefixlen;
	char *if_name = NULL;
	route_entry_t *route;
	bool route_exist = FALSE;

	if (dst->is_anyaddr(dst))
	{
		goto done;
	}
	gateway =
		charon->kernel->get_nexthop(charon->kernel, dst, -1, NULL, &if_name);
	dst_ts->to_subnet(dst_ts, &dst_net, &prefixlen);
	if (!if_name)
	{
		if (src->is_anyaddr(src))
		{
			goto done;
		}
		if (!charon->kernel->get_interface(charon->kernel, src, &if_name))
		{
			goto done;
		}
	}
	route_exist =
		this->routes->find_first(this->routes, route_equals, (void **)&route,
								 if_name, gateway, dst_net, &prefixlen);
	if (add)
	{
		if (route_exist)
		{
			route->refs++;
		}
		else
		{
			KDBG2("installing route: %H/%d via %H dev %s", dst_net, prefixlen,
				  gateway, if_name);
			INIT(route, .if_name = strdup(if_name),
				 .gateway = gateway->clone(gateway),
				 .dst_net = dst_net->clone(dst_net), .prefixlen = prefixlen,
				 .refs = 1, );
			this->routes->insert_last(this->routes, route);
			charon->kernel->add_route(charon->kernel,
									  dst_net->get_address(dst_net), prefixlen,
									  dst, NULL, if_name);
		}
	}
	else
	{
		if (!route_exist || --route->refs > 0)
		{
			goto done;
		}
		KDBG2("uninstalling route: %H/%d via %H dev %s", dst_net, prefixlen,
			  gateway, if_name);
		this->routes->remove(this->routes, route, NULL);
		route_destroy(route);
		charon->kernel->del_route(charon->kernel, dst_net->get_address(dst_net),
								  prefixlen, dst, NULL, if_name);
	}
done:
	if (dst_net)
	{
		dst_net->destroy(dst_net);
	}
	if (gateway)
	{
		gateway->destroy(gateway);
	}
}

/**
 * Hash function for IPsec SA
 */
static u_int
sa_hash(kernel_ipsec_sa_id_t *sa)
{
	return chunk_hash_inc(
		sa->src->get_address(sa->src),
		chunk_hash_inc(
			sa->dst->get_address(sa->dst),
			chunk_hash_inc(chunk_from_thing(sa->spi),
						   chunk_hash(chunk_from_thing(sa->proto)))));
}

/**
 * Equality function for IPsec SA
 */
static bool
sa_equals(kernel_ipsec_sa_id_t *sa, kernel_ipsec_sa_id_t *other_sa)
{
	return sa->src->ip_equals(sa->src, other_sa->src) &&
		   sa->dst->ip_equals(sa->dst, other_sa->dst) &&
		   sa->spi == other_sa->spi && sa->proto == other_sa->proto;
}

/**
 * Hash function for interface
 */
static u_int
interface_hash(char *interface)
{
	return chunk_hash(chunk_from_str(interface));
}

/**
 * Equality function for interface
 */
static bool
interface_equals(char *interface1, char *interface2)
{
	return streq(interface1, interface2);
}

/**
 * Map an integer x with a one-to-one function using quadratic residues
 */
static u_int
permute(u_int x, u_int p)
{
	u_int qr;

	x = x % p;
	qr = ((uint64_t)x * x) % p;
	if (x <= p / 2)
	{
		return qr;
	}
	return p - qr;
}

/**
 * Initialize seeds for SPI generation
 */
static bool
init_spi(private_kernel_vpp_ipsec_t *this)
{
	bool ok = TRUE;
	rng_t *rng;

	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!rng)
	{
		return FALSE;
	}
	ok = rng->get_bytes(rng, sizeof(this->nextspi), (uint8_t *)&this->nextspi);
	if (ok)
	{
		ok =
			rng->get_bytes(rng, sizeof(this->mixspi), (uint8_t *)&this->mixspi);
	}
	rng->destroy(rng);
	return ok;
}

/**
 * Calculate policy priority
 */
static uint32_t
_calculate_priority(policy_priority_t policy_priority, uint16_t pfxlen,
					uint16_t portmasklen, bool has_proto, bool has_intf)
{
	/*
	 * Based on priority calculation from netlink code.
	 *
	 *           1         2         3
	 * 01234567890123456789012345678901
	 * tIppppppXPPPPPPPPPMM
	 *
	 * t bits 0-0:  separate trap and regular policies (0..1) 1 bit
	 * I bits 1-1:  restriction to network interface (0..1)   1 bit
	 * p bits 2-7:  src + dst port mask bits (2 * 0..16)      6 bits
	 * X bits 8-8:  restriction to protocol (0..1)            1 bit
	 * P bits 9-17: src + dst network mask bits (2 * 0..128)  9 bits
	 * F bits 18:   non-fallback bit.                         1 bit
	 */
	uint32_t priority;
	if (policy_priority == POLICY_PRIORITY_FALLBACK)
	{
		priority = (1 << 19);
	}
	else
	{
		priority = (1 << 18);
	}

	/* calculate priority */
	priority -= pfxlen * (1 << 9);
	priority -= has_proto ? (1 << 8) : 0;
	priority -= portmasklen * (1 << 2);
	priority -= has_intf ? (1 << 1) : 0;
	priority -= (policy_priority != POLICY_PRIORITY_ROUTED) * (1 << 0);

	return priority;
}

/**
 * Convert a traffic selector prefix range to prefixlen
 */
static uint8_t
ts2pfxlen(traffic_selector_t *ts)
{
	host_t *net_host;
	uint8_t pfxlen;
	ts->to_subnet(ts, &net_host, &pfxlen);
	net_host->destroy(net_host);
	return pfxlen;
}

/**
 * Convert a traffic selector port range to port/portmask
 */
static uint16_t
ts2portbits(traffic_selector_t *ts)
{
	uint16_t from, to, bitmask;
	int bit, bits = 16;

	from = ts->get_from_port(ts);
	to = ts->get_to_port(ts);

	/* Quick check for a single port */
	if (from == to)
	{
		return 16;
	}
	/* Compute the port mask for port ranges */
	for (bit = 15; bit >= 0; bit--)
	{
		bitmask = 1 << bit;
		if ((bitmask & from) != (bitmask & to))
			return bits;
		bits--;
	}
	return bits;
}

/**
 * Calculate policy priority
 */
static uint32_t
calculate_priority(policy_priority_t policy_priority, traffic_selector_t *src,
				   traffic_selector_t *dst, bool has_intf)
{
	return _calculate_priority(
		policy_priority, ts2pfxlen(src) + ts2pfxlen(dst),
		ts2portbits(src) + ts2portbits(dst),
		(src->get_protocol(src) || dst->get_protocol(dst)), has_intf);
}

/**
 * Get sw_if_index from interface name
 */
static uint32_t
get_sw_if_index(char *interface)
{
	char *out = NULL;
	int out_len;
	vl_api_sw_interface_dump_t *mp;
	vl_api_sw_interface_details_t *rmp, *ermp;
	uint32_t sw_if_index = ~0;
	uint32_t namelen = strlen(interface);

	KDBG4("lookup sw_if_index for %s", interface);

	mp = vl_msg_api_alloc_zero(sizeof(*mp) + namelen);
	mp->_vl_msg_id = VL_API_SW_INTERFACE_DUMP;
#ifdef HAVE_VL_API_C_STRING_TO_API_STRING
	mp->name_filter_valid = 1;
	vl_api_c_string_to_api_string(interface, &mp->name_filter);
#elif defined(HAVE_VPP_API_ENDIAN_FUNCS)
	/* This test is actually to see if we are running >= 20.01 otherwise
	 * namefilter is broken. */
	mp->name_filter_valid = 1;
	vl_api_to_api_string(namelen, interface, &mp->name_filter);
#else
	mp->name_filter_valid = 0;
#endif

	/* Convert to network order and send */
	vl_api_sw_interface_dump_t_endian(mp);
	if (vac->send_dump(vac, (char *)mp, sizeof(*mp) + namelen, &out, &out_len))
	{
		goto error;
	}
	if (!out_len)
	{
		goto error;
	}

	assert((out_len % sizeof(*rmp)) == 0);
	rmp = (void *)out;
	ermp = rmp + out_len / sizeof(*rmp);
	KDBG4("%d entries returned for lookup of %s", ermp - rmp, interface);
	for (; rmp < ermp; rmp++)
	{
		/* Convert to host order */
		vl_api_sw_interface_details_t_endian(rmp);
		if (strlen(rmp->interface_name) == namelen &&
			!strcasecmp(interface, rmp->interface_name))
		{
			sw_if_index = rmp->sw_if_index;
			break;
		}
	}

error:
	free(out);
	vl_msg_api_free(mp);
	KDBG4("GOT sw_if_index %d for %s", sw_if_index, interface);
	return sw_if_index;
}

/**
 * (Un)-install a security policy database
 */
static status_t
spd_add_del(bool add, uint32_t spd_id)
{
	char *out = NULL;
	int out_len;
	vl_api_ipsec_spd_add_del_t *mp;
	vl_api_ipsec_spd_add_del_reply_t *rmp;
	status_t rv = FAILED;

	KDBG3("%s %s SPD %u", __FUNCTION__, add ? "adding" : "removing", spd_id);

	mp = vl_msg_api_alloc_zero(sizeof(*mp));
	mp->_vl_msg_id = VL_API_IPSEC_SPD_ADD_DEL;
	mp->is_add = add;
	mp->spd_id = spd_id;

	/* Convert to network order and send */
	vl_api_ipsec_spd_add_del_t_endian(mp);
	if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
	{
		KDBG1("vac %s SPD failed", add ? "adding" : "removing");
		goto error;
	}

	/* Get reply and convert to host order */
	rmp = (void *)out;
	vl_api_ipsec_spd_add_del_reply_t_endian(rmp);

	if (rmp->retval)
	{
		KDBG1("%s SPD failed rv: %E", add ? "add" : "remove", rmp->retval);
		goto error;
	}

	rv = SUCCESS;

error:
	free(out);
	vl_msg_api_free(mp);
	return rv;
}

/**
 * Enable or disable SPD on an insterface
 */
static status_t
interface_add_del_spd(bool add, uint32_t spd_id, uint32_t sw_if_index)
{
	char *out = NULL;
	int out_len;
	vl_api_ipsec_interface_add_del_spd_t *mp;
	vl_api_ipsec_interface_add_del_spd_reply_t *rmp;
	status_t rv = FAILED;

	KDBG3("%s: INTF %s SPD %d sw_if_index %d", __FUNCTION__,
		  add ? "adding" : "removing", spd_id, sw_if_index);

	mp = vl_msg_api_alloc_zero(sizeof(*mp));
	mp->_vl_msg_id = VL_API_IPSEC_INTERFACE_ADD_DEL_SPD;
	mp->is_add = add;
	mp->spd_id = spd_id;
	mp->sw_if_index = sw_if_index;

	/* Convert to network order and send */
	vl_api_ipsec_interface_add_del_spd_t_endian(mp);
	if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
	{
		KDBG1("vac %s interface SPD failed", add ? "adding" : "removing");
		goto error;
	}

	/* Get reply and convert to host order */
	rmp = (void *)out;
	vl_api_ipsec_interface_add_del_spd_reply_t_endian(rmp);

	if (rmp->retval)
	{
		KDBG1("%s interface SPD failed rv: %E", add ? "add" : "remove",
			  rmp->retval);
		goto error;
	}
	rv = SUCCESS;

error:
	free(out);
	vl_msg_api_free(mp);
	return rv;
}

#define FORIN(val, list)                                                       \
	for (typeof(*list) *__s = list, *__e = __s + sizeof(list) / sizeof(*list), \
					   val;                                                    \
		 __s < __e && (((val) = *__s) || 1); __s++)

static int
bypass_port(bool add, uint32_t spd_id, uint16_t port)
{
	vl_api_ipsec_spd_entry_add_del_t *mp;
	char *out = NULL;
	int out_len;
	status_t rv = FAILED;

	mp = vl_msg_api_alloc_zero(sizeof(*mp));
	mp->_vl_msg_id = VL_API_IPSEC_SPD_ENTRY_ADD_DEL;
	mp->is_add = add;

	mp->entry.spd_id = spd_id;

	memset(&mp->entry.local_address_stop.un, 0xFF,
		   sizeof(mp->entry.local_address_stop.un));
	memset(&mp->entry.remote_address_stop.un, 0xFF,
		   sizeof(mp->entry.remote_address_stop.un));

	KDBG3("BYPASS PORT %s SPD entry spd %d port %d",
		  add ? "adding" : "removing", spd_id, port);

	/*
	 * For both IPv4 and IPv6
	 */
	vl_api_address_family_t families[] = {ADDRESS_IP4, ADDRESS_IP6};
	FORIN(af, families)
	{
		mp->entry.local_address_start.af = af;
		mp->entry.remote_address_start.af = af;
		mp->entry.local_address_stop.af = af;
		mp->entry.remote_address_stop.af = af;

		/*
		 * For ESP, AH and UDP (ESP?).
		 */
		uint8_t protos[] = {IPPROTO_ESP, IPPROTO_AH, IPPROTO_UDP};
		FORIN(proto, protos)
		{
			/* Only install the IP protocol bypass during port 500 bypass */
			if (port != 500 && proto != IPPROTO_UDP)
			{
				continue;
			}
			uint16_t nport = (proto == IPPROTO_UDP) ? port : 0;
			mp->entry.protocol = proto;
			mp->entry.local_port_start = nport;
			mp->entry.local_port_stop = nport;
			mp->entry.remote_port_start = nport;
			mp->entry.remote_port_stop = nport;

			mp->entry.priority =
				_calculate_priority(POLICY_PRIORITY_PASS, 0,
									proto == IPPROTO_UDP ? 32 : 0, TRUE, TRUE);
			mp->entry.priority = INT_MAX - mp->entry.priority;

			/*
			 * For inbound and outbound
			 */
			for (int outbound = 0; outbound <= 1; outbound++)
			{
				mp->entry.is_outbound = outbound;
				KDBG3("BYPASS PORT %s entry family %d proto %d outbound %d",
					  add ? "adding" : "removing", af, proto, outbound);

				/* Conver to network order and send */
				vl_api_ipsec_spd_entry_add_del_t_endian(mp);
				if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
				{
					KDBG1("vac %s SPD entry failed",
						  add ? "adding" : "removing");
					goto error;
				}
				/* Convert back to host order for re-use */
				vl_api_ipsec_spd_entry_add_del_t_endian(mp);

				/* Get reply and convert to host order */
				vl_api_ipsec_spd_entry_add_del_reply_t *rmp = (void *)out;
				vl_api_ipsec_spd_entry_add_del_reply_t_endian(rmp);
				int vrv = rmp->retval;
				free(out);

				if (vrv)
				{
					KDBG1("%s SPD entry failed rv: %E", add ? "add" : "remove",
						  vrv);
					goto error;
				}
			}
		}
	}
	rv = SUCCESS;

error:
	vl_msg_api_free(mp);
	return rv;
}

/**
 * Add or remove a bypass policy
 */
static status_t
manage_bypass(bool add, uint32_t spd_id)
{
	uint16_t port;
	status_t rv;

	port = lib->settings->get_int(lib->settings, "%s.port", IKEV2_UDP_PORT,
								  lib->ns);

	if (port)
	{
		rv = bypass_port(add, spd_id, port);
		if (rv != SUCCESS)
		{
			return rv;
		}
	}

	port = lib->settings->get_int(lib->settings, "%s.port_nat_t",
								  IKEV2_NATT_PORT, lib->ns);
	if (port)
	{
		rv = bypass_port(add, spd_id, port);
		if (rv != SUCCESS)
		{
			return rv;
		}
	}

	return SUCCESS;
}

/**
 * Add or remove a policy
 */
static status_t
manage_policy(private_kernel_vpp_ipsec_t *this, bool add,
			  kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
	spd_t *spd;
	char *out = NULL, *interface;
	int out_len;
	uint32_t sw_if_index, spd_id, *sad_id;
	status_t rv = FAILED;
	uint32_t priority, auto_priority;
	traffic_selector_t *local, *remote;
	chunk_t local_from, local_to, remote_from, remote_to;
	vl_api_ipsec_spd_entry_add_del_t *mp;
	vl_api_ipsec_spd_entry_add_del_reply_t *rmp;

	mp = vl_msg_api_alloc_zero(sizeof(*mp));

	this->mutex->lock(this->mutex);
	if (!id->interface)
	{
		host_t *addr = id->dir == POLICY_IN ? data->dst : data->src;
		if (!charon->kernel->get_interface(charon->kernel, addr, &interface))
		{
			KDBG1("policy no interface %H", addr);
			goto error;
		}
		id->interface = interface;
	}
	spd = this->spds->get(this->spds, id->interface);
	if (!spd)
	{
		if (!add)
		{
			KDBG1("SPD for %s not found", id->interface);
			goto error;
		}
		sw_if_index = get_sw_if_index(id->interface);
		if (sw_if_index == ~0)
		{
			KDBG1("sw_if_index for %s not found", id->interface);
			goto error;
		}
		spd_id = ref_get(&this->next_spd_id);
		if (spd_add_del(TRUE, spd_id))
		{
			goto error;
		}
		/* XXX this is going to bypass for both IPv4 and IPv6 is that right? */
		/* Since we only due this once for a spd it has to be or get more
		   complex (tracking per family bypass) probably want this */
		if (manage_bypass(TRUE, spd_id))
		{
			goto error;
		}
		if (interface_add_del_spd(TRUE, spd_id, sw_if_index))
		{
			goto error;
		}
		INIT(spd, .spd_id = spd_id, .sw_if_index = sw_if_index,
			 .policy_num = 0, );
		this->spds->put(this->spds, id->interface, spd);
	}

	auto_priority =
		calculate_priority(data->prio, id->src_ts, id->dst_ts, TRUE);
	priority = data->manual_prio ? data->manual_prio : auto_priority;

	mp->_vl_msg_id = VL_API_IPSEC_SPD_ENTRY_ADD_DEL;
	mp->is_add = add;
	mp->entry.spd_id = spd->spd_id;
	/*
	 * linux and swans treat smaller priority as higher :(
	 * VPP treats lower priority values as lower priority so reverse.
	 */
	mp->entry.priority = INT_MAX - priority;
	mp->entry.is_outbound = id->dir == POLICY_OUT;
	switch (data->type)
	{
	case POLICY_IPSEC:
		mp->entry.policy = IPSEC_API_SPD_ACTION_PROTECT;
		break;
	case POLICY_PASS:
		mp->entry.policy = IPSEC_API_SPD_ACTION_BYPASS;
		break;
	case POLICY_DROP:
		mp->entry.policy = IPSEC_API_SPD_ACTION_DISCARD;
		break;
		/* XXX: IPSEC_API_SPD_ACTION_RESOLVE? */
	}

	if ((data->type == POLICY_IPSEC) && data->sa)
	{
		kernel_ipsec_sa_id_t id = {
			.src = data->src,
			.dst = data->dst,
			.proto = data->sa->esp.use ? IPPROTO_ESP : IPPROTO_AH,
			.spi = data->sa->esp.use ? data->sa->esp.spi : data->sa->ah.spi,
		};
		sad_id = this->sas->get(this->sas, &id);
		if (!sad_id)
		{
			KDBG1("SA ID not found");
			goto error;
		}
		mp->entry.sa_id = *sad_id;
	}

	/* IP protocol */
	mp->entry.protocol = id->src_ts->get_protocol(id->src_ts);
	if (id->dir == POLICY_OUT)
	{
		local = id->src_ts;
		remote = id->dst_ts;
	}
	else
	{
		remote = id->src_ts;
		local = id->dst_ts;
	}

	local_from = local->get_from_address(local);
	local_to = local->get_to_address(local);
	remote_from = remote->get_from_address(remote);
	remote_to = remote->get_to_address(remote);

	chunk_to_api(local_from, &mp->entry.local_address_start);
	chunk_to_api(local_to, &mp->entry.local_address_stop);
	chunk_to_api(remote_from, &mp->entry.remote_address_start);
	chunk_to_api(remote_to, &mp->entry.remote_address_stop);

	mp->entry.local_port_start = local->get_from_port(local);
	mp->entry.local_port_stop = local->get_to_port(local);
	mp->entry.remote_port_start = remote->get_from_port(remote);
	mp->entry.remote_port_stop = remote->get_to_port(remote);

	/* Convert to network order */
	vl_api_ipsec_spd_entry_add_del_t_endian(mp);
	if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
	{
		KDBG1("vac %s SPD entry failed", add ? "adding" : "removing");
		goto error;
	}

	/* Get result and convert to host order */
	rmp = (void *)out;
	vl_api_ipsec_spd_entry_add_del_reply_t_endian(rmp);

	if (rmp->retval)
	{
		KDBG1("%s SPD entry failed rv: %E", add ? "add" : "remove",
			  rmp->retval);
		goto error;
	}
	if (add)
	{
		ref_get(&spd->policy_num);
	}
	else
	{
		if (ref_put(&spd->policy_num))
		{
			interface_add_del_spd(FALSE, spd->spd_id, spd->sw_if_index);
			manage_bypass(FALSE, spd->spd_id);
			spd_add_del(FALSE, spd->spd_id);
			this->spds->remove(this->spds, id->interface);
		}
	}
	if (this->install_routes && id->dir == POLICY_OUT && !mp->entry.protocol)
	{
		if (data->type == POLICY_IPSEC && data->sa->mode != MODE_TRANSPORT)
		{
			manage_route(this, add, id->dst_ts, data->src, data->dst);
		}
	}
	rv = SUCCESS;
error:
	free(out);
	vl_msg_api_free(mp);
	this->mutex->unlock(this->mutex);
	return rv;
}

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
	   private_kernel_vpp_ipsec_t *this)
{
	return KERNEL_ESP_V3_TFC;
}

METHOD(kernel_ipsec_t, get_spi, status_t, private_kernel_vpp_ipsec_t *this,
	   host_t *src, host_t *dst, uint8_t protocol, uint32_t *spi)
{
	static const u_int p = 268435399, offset = 0xc0000000;

	/* XXX is this htonl correct or are we wrong elsewhere?? */
	*spi = htonl(offset + permute(ref_get(&this->nextspi) ^ this->mixspi, p));
	return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t, private_kernel_vpp_ipsec_t *this,
	   host_t *src, host_t *dst, uint16_t *cpi)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_sa, status_t, private_kernel_vpp_ipsec_t *this,
	   kernel_ipsec_sa_id_t *id, kernel_ipsec_add_sa_t *data)
{
	char *out = NULL;
	int out_len;
	vl_api_ipsec_sad_entry_add_del_t *mp;
	vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
	uint32_t sad_id = ref_get(&this->next_sad_id);
	uint8_t ca = 0, ia = 0;
	status_t rv = FAILED;
	kernel_ipsec_sa_id_t *sa_id = NULL;
	sa_t *sa = NULL;
	int key_len = data->enc_key.len;

	if ((data->enc_alg == ENCR_AES_CTR) ||
		(data->enc_alg == ENCR_AES_GCM_ICV8) ||
		(data->enc_alg == ENCR_AES_GCM_ICV12) ||
		(data->enc_alg == ENCR_AES_GCM_ICV16))
	{
		static const int SALT_SIZE = 4; /* See how enc_size is calculated at
										   keymat_v2.derive_child_keys */
		key_len = key_len - SALT_SIZE;
	}

	mp = vl_msg_api_alloc_zero(sizeof(*mp));
	mp->_vl_msg_id = VL_API_IPSEC_SAD_ENTRY_ADD_DEL;
	mp->is_add = 1;
	mp->entry.sad_id = sad_id;
	mp->entry.spi = id->spi;
	if (id->proto == IPPROTO_ESP)
	{
		mp->entry.protocol = IPSEC_API_PROTO_ESP;
	}
	else
	{
		assert(id->proto == IPPROTO_AH);
		mp->entry.protocol = IPSEC_API_PROTO_AH;
	}
	switch (data->enc_alg)
	{
	case ENCR_NULL:
		ca = IPSEC_CRYPTO_ALG_NONE;
		break;
	case ENCR_AES_CBC:
		switch (key_len * 8)
		{
		case 128:
			ca = IPSEC_CRYPTO_ALG_AES_CBC_128;
			break;
		case 192:
			ca = IPSEC_CRYPTO_ALG_AES_CBC_192;
			break;
		case 256:
			ca = IPSEC_CRYPTO_ALG_AES_CBC_256;
			break;
		default:
			KDBG1("Key length %d is not supported by VPP!", key_len * 8);
			break;
		}
		break;
	case ENCR_AES_CTR:
		switch (key_len * 8)
		{
		case 128:
			ca = IPSEC_CRYPTO_ALG_AES_CTR_128;
			break;
		case 192:
			ca = IPSEC_CRYPTO_ALG_AES_CTR_192;
			break;
		case 256:
			ca = IPSEC_CRYPTO_ALG_AES_CTR_256;
			break;
		default:
			KDBG1("Key length %d is not supported by VPP!", key_len * 8);
			goto error;
			break;
		}
		break;
	case ENCR_AES_GCM_ICV8:
	case ENCR_AES_GCM_ICV12:
	case ENCR_AES_GCM_ICV16:
		switch (key_len * 8)
		{
		case 128:
			ca = IPSEC_CRYPTO_ALG_AES_GCM_128;
			break;
		case 192:
			ca = IPSEC_CRYPTO_ALG_AES_GCM_192;
			break;
		case 256:
			ca = IPSEC_CRYPTO_ALG_AES_GCM_256;
			break;
		default:
			KDBG1("Key length %d is not supported by VPP!", key_len * 8);
			goto error;
			break;
		}
		mp->entry.salt = ((u8)data->enc_key.ptr[key_len] << 24) +
						 ((u8)data->enc_key.ptr[key_len + 1] << 16) +
						 ((u8)data->enc_key.ptr[key_len + 2] << 8) +
						 (u8)data->enc_key.ptr[key_len + 3];
		mp->entry.salt = mp->entry.salt;
		break;
	case ENCR_DES:
		ca = IPSEC_CRYPTO_ALG_DES_CBC;
		break;
	case ENCR_3DES:
		ca = IPSEC_CRYPTO_ALG_3DES_CBC;
		break;
	default:
		KDBG1("algorithm %N not supported by VPP!", encryption_algorithm_names,
			  data->enc_alg);
		goto error;
		break;
	}
	mp->entry.crypto_algorithm = ca;
	mp->entry.crypto_key.length = key_len;
	memcpy(mp->entry.crypto_key.data, data->enc_key.ptr, key_len);
	switch (data->int_alg)
	{
	case AUTH_UNDEFINED:
		ia = IPSEC_INTEG_ALG_NONE;
		break;
	case AUTH_HMAC_MD5_96:
		ia = IPSEC_INTEG_ALG_MD5_96;
		break;
	case AUTH_HMAC_SHA1_96:
		ia = IPSEC_INTEG_ALG_SHA1_96;
		break;
	case AUTH_HMAC_SHA2_256_96:
		ia = IPSEC_INTEG_ALG_SHA_256_96;
		break;
	case AUTH_HMAC_SHA2_256_128:
		ia = IPSEC_INTEG_ALG_SHA_256_128;
		break;
	case AUTH_HMAC_SHA2_384_192:
		ia = IPSEC_INTEG_ALG_SHA_384_192;
		break;
	case AUTH_HMAC_SHA2_512_256:
		ia = IPSEC_INTEG_ALG_SHA_512_256;
		break;
	default:
		KDBG1("algorithm %N not supported by VPP!", integrity_algorithm_names,
			  data->int_alg);
		goto error;
		break;
	}
	mp->entry.integrity_algorithm = ia;
	mp->entry.integrity_key.length = data->int_key.len;
	memcpy(mp->entry.integrity_key.data, data->int_key.ptr, data->int_key.len);

	uint32_t flags = 0;
	if (data->esn)
	{
		flags |= IPSEC_API_SAD_FLAG_USE_ESN;
	}
	if (data->replay_window)
	{
		flags |= IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY;
	}
	if (data->mode == MODE_TUNNEL)
	{
		flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL;
		if (id->src->get_family(id->src) == AF_INET6)
		{
			flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL_V6;
		}
	}
	if (data->encap)
	{
		flags |= IPSEC_API_SAD_FLAG_UDP_ENCAP;
	}
#ifdef HAVE_IPSEC_API_SAD_FLAG_IS_INBOUND
	if (data->inbound)
	{
		flags |= IPSEC_API_SAD_FLAG_IS_INBOUND;
	}
#endif
	/*
	 * Unmappable strongswan features:
	 * - data->hw_offload
	 * - data->mark
	 * - data->copy_df
	 * - data->copy_ecn
	 * - data->copy_dscp
	 */
	mp->entry.flags = flags;
	chunk_to_api(id->src->get_address(id->src), &mp->entry.tunnel_src);
	chunk_to_api(id->dst->get_address(id->dst), &mp->entry.tunnel_dst);
	KDBG3("add SA tunnel said %d src %H dst %H enc %N keylen %d spi %d",
		  mp->entry.sad_id, id->src, id->dst, encryption_algorithm_names,
		  data->enc_alg, key_len, mp->entry.spi);

	/* Convert message to network order and send */
	vl_api_ipsec_sad_entry_add_del_t_endian(mp);
	if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
	{
		KDBG1("vac adding SA failed %s");
		goto error;
	}

	/* Get reply and convert to host order */
	rmp = (void *)out;
	vl_api_ipsec_sad_entry_add_del_reply_t_endian(rmp);

	if (rmp->retval)
	{
		KDBG1("add SA failed rv: %E", rmp->retval);
		goto error;
	}

	this->mutex->lock(this->mutex);
	INIT(sa_id, .src = id->src->clone(id->src), .dst = id->dst->clone(id->dst),
		 .spi = id->spi, .proto = id->proto, );
	INIT(sa, .sa_id = sad_id, .mp = mp, );
	this->sas->put(this->sas, sa_id, sa);
	this->mutex->unlock(this->mutex);
	rv = SUCCESS;

error:
	free(out);
	return rv;
}

METHOD(kernel_ipsec_t, update_sa, status_t, private_kernel_vpp_ipsec_t *this,
	   kernel_ipsec_sa_id_t *id, kernel_ipsec_update_sa_t *data)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, query_sa, status_t, private_kernel_vpp_ipsec_t *this,
	   kernel_ipsec_sa_id_t *id, kernel_ipsec_query_sa_t *data, uint64_t *bytes,
	   uint64_t *packets, time_t *time)
{
	char *out = NULL;
	int out_len;
	vl_api_ipsec_sa_dump_t *mp;
	status_t rv = FAILED;
	sa_t *sa;

	KDBG3("query SA: ID: spi %u src %H dst %H proto %d mark %d ifid %d",
		  id->spi, id->src, id->dst, id->proto, id->mark, id->if_id);

	this->mutex->lock(this->mutex);
	sa = this->sas->get(this->sas, id);
	this->mutex->unlock(this->mutex);
	if (!sa)
	{
		KDBG1("SA not found");
		return NOT_FOUND;
	}

	mp = vl_msg_api_alloc_zero(sizeof(*mp));
	mp->_vl_msg_id = VL_API_IPSEC_SA_DUMP;
	mp->sa_id = sa->sa_id;

	/* Convert to network order and send */
	vl_api_ipsec_sa_dump_t_endian(mp);
	if (vac->send_dump(vac, (char *)mp, sizeof(*mp), &out, &out_len))
	{
		KDBG1("vac SA dump failed");
		goto error;
	}
	if (!out_len)
	{
		KDBG1("SA ID %d no data", sa->sa_id);
		rv = NOT_FOUND;
		goto error;
	}

	vl_api_ipsec_sad_entry_t *entry = &sa->mp->entry;
	host_t *sa_tun_src = addr_to_host(&entry->tunnel_src);
	host_t *sa_tun_dst = addr_to_host(&entry->tunnel_dst);
	KDBG3("query SA: found SA: sa_id %u ENTRY: sad_id %u spi %u src %H dst %H "
		  "proto %d table_id %d",
		  sa->sa_id, entry->sad_id, entry->spi, sa_tun_src, sa_tun_dst,
		  entry->protocol, entry->tx_table_id);
	free(sa_tun_src);
	free(sa_tun_dst);

	if (bytes)
	{
#if 0
		/* Convert reply to host order */
		vl_api_ipsec_sa_details_t *rmp = (void *)out;
		vl_api_ipsec_sa_details_t_endian(rmp);
		/*
		 * There's a stat index in VPP 20.05; however, we have no easy way of
		 * getting that statistic here yet. This is too bad b/c I believe this
		 * counter is used for aging out keys.
		 */
		(void)rmp->stat_index;
#else
		*bytes = 0;
#endif
	}
	if (packets)
	{
		*packets = 0;
	}
	if (time)
	{
		*time = 0;
	}
	rv = SUCCESS;
error:
	free(out);
	vl_msg_api_free(mp);
	return rv;
}

METHOD(kernel_ipsec_t, del_sa, status_t, private_kernel_vpp_ipsec_t *this,
	   kernel_ipsec_sa_id_t *id, kernel_ipsec_del_sa_t *data)
{
	char *out = NULL;
	int out_len;
	vl_api_ipsec_sad_entry_add_del_t *mp;
	vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
	status_t rv = FAILED;
	sa_t *sa;

	this->mutex->lock(this->mutex);
	sa = this->sas->get(this->sas, id);
	if (!sa)
	{
		KDBG1("SA not found");
		rv = NOT_FOUND;
		goto error;
	}
	mp = sa->mp;
	mp->is_add = 0;

	if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
	{
		KDBG1("vac removing SA failed");
		goto error;
	}
	rmp = (void *)out;
	if (rmp->retval)
	{
		KDBG1("del SA failed rv: %E", rmp->retval);
		goto error;
	}
	/* XXX chopps: don't we need to free our sa entry??? */
	sa->mp = NULL;
	vl_msg_api_free(mp);
	this->sas->remove(this->sas, id);
	rv = SUCCESS;
error:
	free(out);
	this->mutex->unlock(this->mutex);
	return rv;
}

METHOD(kernel_ipsec_t, flush_sas, status_t, private_kernel_vpp_ipsec_t *this)
{
	enumerator_t *enumerator;
	int out_len;
	char *out;
	vl_api_ipsec_sad_entry_add_del_t *mp;
	sa_t *sa = NULL;

	this->mutex->lock(this->mutex);
	enumerator = this->sas->create_enumerator(this->sas);
	while (enumerator->enumerate(enumerator, sa, NULL))
	{
		mp = sa->mp;
		mp->is_add = 0;
		if (vac->send(vac, (char *)mp, sizeof(*mp), &out, &out_len))
		{
			break;
		}
		free(out);
		vl_msg_api_free(mp);
		this->sas->remove_at(this->sas, enumerator);
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	return SUCCESS;
}

METHOD(kernel_ipsec_t, add_policy, status_t, private_kernel_vpp_ipsec_t *this,
	   kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
	return manage_policy(this, TRUE, id, data);
}

METHOD(kernel_ipsec_t, query_policy, status_t, private_kernel_vpp_ipsec_t *this,
	   kernel_ipsec_policy_id_t *id, kernel_ipsec_query_policy_t *data,
	   time_t *use_time)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t, private_kernel_vpp_ipsec_t *this,
	   kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
	return manage_policy(this, FALSE, id, data);
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	   private_kernel_vpp_ipsec_t *this)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, bypass_socket, bool, private_kernel_vpp_ipsec_t *this,
	   int fd, int family)
{
	return FALSE;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool, private_kernel_vpp_ipsec_t *this,
	   int fd, int family, u_int16_t port)
{
	return FALSE;
}

METHOD(kernel_ipsec_t, destroy, void, private_kernel_vpp_ipsec_t *this)
{
	this->mutex->destroy(this->mutex);
	this->sas->destroy(this->sas);
	this->spds->destroy(this->spds);
	this->routes->destroy(this->routes);
	free(this);
}

kernel_vpp_ipsec_t *
kernel_vpp_ipsec_create()
{
	private_kernel_vpp_ipsec_t *this;

	INIT(this,
		 .public = {.interface = {.get_features = _get_features,
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
								  .bypass_socket = _bypass_socket,
								  .enable_udp_decap = _enable_udp_decap,
								  .destroy = _destroy}},
		 .next_sad_id = 0, .next_spd_id = 0,
		 .mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		 .sas = hashtable_create((hashtable_hash_t)sa_hash,
								 (hashtable_equals_t)sa_equals, 32),
		 .spds = hashtable_create((hashtable_hash_t)interface_hash,
								  (hashtable_equals_t)interface_equals, 4),
		 .routes = linked_list_create(),
		 .install_routes = lib->settings->get_bool(
			 lib->settings, "%s.install_routes", TRUE, lib->ns));

	if (!init_spi(this))
	{
		destroy(this);
		return NULL;
	}

	return &this->public;
}

/*
 * fd.io coding-style-patch-verification: CLANG
 *
 * Local Variables:
 * c-file-style: "bsd"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 */
