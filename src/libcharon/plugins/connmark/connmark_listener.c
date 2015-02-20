/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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

#include "connmark_listener.h"

#include <daemon.h>

#include <errno.h>
#include <libiptc/libiptc.h>
#include <linux/netfilter/xt_esp.h>
#include <linux/netfilter/xt_tcpudp.h>
#include <linux/netfilter/xt_MARK.h>
#include <linux/netfilter/xt_policy.h>
#include <linux/netfilter/xt_CONNMARK.h>


typedef struct private_connmark_listener_t private_connmark_listener_t;

/**
 * Private data of an connmark_listener_t object.
 */
struct private_connmark_listener_t {

	/**
	 * Public connmark_listener_t interface.
	 */
	connmark_listener_t public;
};

/**
 * Convert an (IPv4) traffic selector to an address and mask
 */
static bool ts2in(traffic_selector_t *ts,
				  struct in_addr *addr, struct in_addr *mask)
{
	u_int8_t bits;
	host_t *net;

	if (ts->get_type(ts) == TS_IPV4_ADDR_RANGE &&
		ts->to_subnet(ts, &net, &bits))
	{
		memcpy(&addr->s_addr, net->get_address(net).ptr, 4);
		net->destroy(net);
		mask->s_addr = htonl(0xffffffffU << (32 - bits));
		return TRUE;
	}
	return FALSE;
}

/**
 * Convert an (IPv4) host to an address with mask
 */
static bool host2in(host_t *host, struct in_addr *addr, struct in_addr *mask)
{
	if (host->get_family(host) == AF_INET)
	{
		memcpy(&addr->s_addr, host->get_address(host).ptr, 4);
		mask->s_addr = ~0;
		return TRUE;
	}
	return FALSE;
}

/**
 * Add or remove a rule to/from the specified chain
 */
static bool manage_rule(struct iptc_handle *ipth, const char *chain,
						bool add, struct ipt_entry *e)
{
	if (add)
	{
		if (!iptc_insert_entry(chain, e, 0, ipth))
		{
			DBG1(DBG_CFG, "appending %s rule failed: %s",
				 chain, iptc_strerror(errno));
			return FALSE;
		}
	}
	else
	{
		if (!iptc_delete_entry(chain, e, "", ipth))
		{
			DBG1(DBG_CFG, "deleting %s rule failed: %s",
				 chain, iptc_strerror(errno));
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Add rule marking UDP-encapsulated ESP packets to match the correct policy
 */
static bool manage_pre_esp_in_udp(private_connmark_listener_t *this,
								  struct iptc_handle *ipth, bool add,
								  u_int mark, u_int32_t spi,
								  host_t *dst, host_t *src)
{
	struct {
		struct ipt_entry e;
		struct ipt_entry_match m;
		struct xt_udp udp;
		struct ipt_entry_target t;
		struct xt_mark_tginfo2 tm;
	} ipt = {
		.e  = {
			.target_offset = XT_ALIGN(sizeof(ipt.e) + sizeof(ipt.m) +
									  sizeof(ipt.udp)),
			.next_offset = sizeof(ipt),
			.ip = {
				.proto = IPPROTO_UDP,
			},
		},
		.m = {
			.u = {
				.user = {
					.match_size = XT_ALIGN(sizeof(ipt.m) + sizeof(ipt.udp)),
					.name = "udp",
				},
			},
		},
		.udp = {
			.spts = { src->get_port(src), src->get_port(src) },
			.dpts = { dst->get_port(dst), dst->get_port(dst) },
		},
		.t = {
			.u = {
				.user = {
					.target_size = XT_ALIGN(sizeof(ipt.t) + sizeof(ipt.tm)),
					.name = "MARK",
					.revision = 2,
				},
			},
		},
		.tm = {
			.mark = mark,
			.mask = ~0,
		},
	};

	if (!host2in(dst, &ipt.e.ip.dst, &ipt.e.ip.dmsk) ||
		!host2in(src, &ipt.e.ip.src, &ipt.e.ip.smsk))
	{
		return FALSE;
	}
	return manage_rule(ipth, "PREROUTING", add, &ipt.e);
}

/**
 * Add rule marking non-encapsulated ESP packets to match the correct policy
 */
static bool manage_pre_esp(private_connmark_listener_t *this,
						   struct iptc_handle *ipth, bool add,
						   u_int mark, u_int32_t spi,
						   host_t *dst, host_t *src)
{
	struct {
		struct ipt_entry e;
		struct ipt_entry_match m;
		struct xt_esp esp;
		struct ipt_entry_target t;
		struct xt_mark_tginfo2 tm;
	} ipt = {
		.e  = {
			.target_offset = XT_ALIGN(sizeof(ipt.e) + sizeof(ipt.m) +
									  sizeof(ipt.esp)),
			.next_offset = sizeof(ipt),
			.ip = {
				.proto = IPPROTO_ESP,
			},
		},
		.m = {
			.u = {
				.user = {
					.match_size = XT_ALIGN(sizeof(ipt.m) + sizeof(ipt.esp)),
					.name = "esp",
				},
			},
		},
		.esp = {
			.spis = { htonl(spi), htonl(spi) },
		},
		.t = {
			.u = {
				.user = {
					.target_size = XT_ALIGN(sizeof(ipt.t) + sizeof(ipt.tm)),
					.name = "MARK",
					.revision = 2,
				},
			},
		},
		.tm = {
			.mark = mark,
			.mask = ~0,
		},
	};

	if (!host2in(dst, &ipt.e.ip.dst, &ipt.e.ip.dmsk) ||
		!host2in(src, &ipt.e.ip.src, &ipt.e.ip.smsk))
	{
		return FALSE;
	}
	return manage_rule(ipth, "PREROUTING", add, &ipt.e);
}

/**
 * Add rule marking ESP packets to match the correct policy
 */
static bool manage_pre(private_connmark_listener_t *this,
					   struct iptc_handle *ipth, bool add,
					   u_int mark, u_int32_t spi, bool encap,
					   host_t *dst, host_t *src)
{
	if (encap)
	{
		return manage_pre_esp_in_udp(this, ipth, add, mark, spi, dst, src);
	}
	return manage_pre_esp(this, ipth, add, mark, spi, dst, src);
}

/**
 * Add inbound rule applying CONNMARK to matching traffic
 */
static bool manage_in(private_connmark_listener_t *this,
					  struct iptc_handle *ipth, bool add,
					  u_int mark, u_int32_t spi,
					  traffic_selector_t *dst, traffic_selector_t *src)
{
	struct {
		struct ipt_entry e;
		struct ipt_entry_match m;
		struct xt_policy_info p;
		struct ipt_entry_target t;
		struct xt_connmark_tginfo1 cm;
	} ipt = {
		.e  = {
			.target_offset = XT_ALIGN(sizeof(ipt.e) + sizeof(ipt.m) +
									  sizeof(ipt.p)),
			.next_offset = sizeof(ipt),
		},
		.m = {
			.u = {
				.user = {
					.match_size = XT_ALIGN(sizeof(ipt.m) + sizeof(ipt.p)),
					.name = "policy",
				},
			},
		},
		.p = {
			.pol = {
				{
					.spi = spi,
					.match.spi = 1,
				},
			},
			.len = 1,
			.flags = XT_POLICY_MATCH_IN,
		},
		.t = {
			.u = {
				.user = {
					.target_size = XT_ALIGN(sizeof(ipt.t) + sizeof(ipt.cm)),
					.name = "CONNMARK",
					.revision = 1,
				},
			},
		},
		.cm = {
			.ctmark = mark,
			.ctmask = ~0,
			.nfmask = ~0,
			.mode = XT_CONNMARK_SET,
		},
	};

	if (!ts2in(dst, &ipt.e.ip.dst, &ipt.e.ip.dmsk) ||
		!ts2in(src, &ipt.e.ip.src, &ipt.e.ip.smsk))
	{
		return FALSE;
	}
	return manage_rule(ipth, "INPUT", add, &ipt.e);
}

/**
 * Add outbund rule restoring CONNMARK on matching traffic
 */
static bool manage_out(private_connmark_listener_t *this,
					   struct iptc_handle *ipth, bool add,
					   traffic_selector_t *dst, traffic_selector_t *src)
{
	struct {
		struct ipt_entry e;
		struct ipt_entry_target t;
		struct xt_connmark_tginfo1 cm;
	} ipt = {
		.e  = {
			.target_offset = XT_ALIGN(sizeof(ipt.e)),
			.next_offset = sizeof(ipt),
		},
		.t = {
			.u = {
				.user = {
					.target_size = XT_ALIGN(sizeof(ipt.t) + sizeof(ipt.cm)),
					.name = "CONNMARK",
					.revision = 1,
				},
			},
		},
		.cm = {
			.ctmask = ~0,
			.nfmask = ~0,
			.mode = XT_CONNMARK_RESTORE,
		},
	};

	if (!ts2in(dst, &ipt.e.ip.dst, &ipt.e.ip.dmsk) ||
		!ts2in(src, &ipt.e.ip.src, &ipt.e.ip.smsk))
	{
		return FALSE;
	}
	return manage_rule(ipth, "OUTPUT", add, &ipt.e);
}

/**
 * Initialize iptables handle, log error
 */
static struct iptc_handle* init_handle()
{
	struct iptc_handle *ipth;

	ipth = iptc_init("mangle");
	if (ipth)
	{
		return ipth;
	}
	DBG1(DBG_CFG, "initializing iptables failed: %s", iptc_strerror(errno));
	return NULL;
}

/**
 * Commit iptables rules, log error
 */
static bool commit_handle(struct iptc_handle *ipth)
{
	if (iptc_commit(ipth))
	{
		return TRUE;
	}
	DBG1(DBG_CFG, "forecast iptables commit failed: %s", iptc_strerror(errno));
	return FALSE;
}

/**
 * Add/Remove policies for a CHILD_SA using a iptables handle
 */
static bool manage_policies(private_connmark_listener_t *this,
						struct iptc_handle *ipth, host_t *dst, host_t *src,
						bool encap, child_sa_t *child_sa, bool add)
{
	traffic_selector_t *local, *remote;
	enumerator_t *enumerator;
	u_int32_t spi;
	u_int mark;
	bool done = TRUE;

	spi = child_sa->get_spi(child_sa, TRUE);
	mark = child_sa->get_mark(child_sa, TRUE).value;

	enumerator = child_sa->create_policy_enumerator(child_sa);
	while (enumerator->enumerate(enumerator, &local, &remote))
	{
		if (!manage_pre(this, ipth, add, mark, spi, encap, dst, src) ||
			!manage_in(this, ipth, add, mark, spi, local, remote) ||
			!manage_out(this, ipth, add, remote, local))
		{
			done = FALSE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	return done;
}

/**
 * Check if rules should be installed for given CHILD_SA
 */
static bool handle_sa(child_sa_t *child_sa)
{
	return child_sa->get_mark(child_sa, TRUE).value &&
		   child_sa->get_mark(child_sa, FALSE).value &&
		   child_sa->get_mode(child_sa) == MODE_TRANSPORT &&
		   child_sa->get_protocol(child_sa) == PROTO_ESP;
}

METHOD(listener_t, child_updown, bool,
	private_connmark_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	bool up)
{
	struct iptc_handle *ipth;
	host_t *dst, *src;
	bool encap;

	dst = ike_sa->get_my_host(ike_sa);
	src = ike_sa->get_other_host(ike_sa);
	encap = child_sa->has_encap(child_sa);

	if (handle_sa(child_sa))
	{
		ipth = init_handle();
		if (ipth)
		{
			if (manage_policies(this, ipth, dst, src, encap, child_sa, up))
			{
				commit_handle(ipth);
			}
			iptc_free(ipth);
		}
	}
	return TRUE;
}

METHOD(listener_t, child_rekey, bool,
	private_connmark_listener_t *this, ike_sa_t *ike_sa,
	child_sa_t *old, child_sa_t *new)
{
	struct iptc_handle *ipth;
	host_t *dst, *src;
	bool oldencap, newencap;

	dst = ike_sa->get_my_host(ike_sa);
	src = ike_sa->get_other_host(ike_sa);
	oldencap = old->has_encap(old);
	newencap = new->has_encap(new);

	if (handle_sa(old))
	{
		ipth = init_handle();
		if (ipth)
		{
			if (manage_policies(this, ipth, dst, src, oldencap, old, FALSE) &&
				manage_policies(this, ipth, dst, src, newencap, new, TRUE))
			{
				commit_handle(ipth);
			}
			iptc_free(ipth);
		}
	}
	return TRUE;
}

METHOD(listener_t, ike_update, bool,
	private_connmark_listener_t *this, ike_sa_t *ike_sa,
	bool local, host_t *new)
{
	struct iptc_handle *ipth;
	enumerator_t *enumerator;
	child_sa_t *child_sa;
	host_t *dst, *src;
	bool oldencap, newencap;

	if (local)
	{
		dst = new;
		src = ike_sa->get_other_host(ike_sa);
	}
	else
	{
		dst = ike_sa->get_my_host(ike_sa);
		src = new;
	}
	/* during ike_update(), has_encap() on the CHILD_SA has not yet been
	 * updated, but shows the old state. */
	newencap = ike_sa->has_condition(ike_sa, COND_NAT_ANY);

	enumerator = ike_sa->create_child_sa_enumerator(ike_sa);
	while (enumerator->enumerate(enumerator, &child_sa))
	{
		if (handle_sa(child_sa))
		{
			oldencap = child_sa->has_encap(child_sa);
			ipth = init_handle();
			if (ipth)
			{
				if (manage_policies(this, ipth, dst, src, oldencap,
									child_sa, FALSE) &&
					manage_policies(this, ipth, dst, src, newencap,
									child_sa, TRUE))
				{
					commit_handle(ipth);
				}
				iptc_free(ipth);
			}
		}
	}
	enumerator->destroy(enumerator);

	return TRUE;
}

METHOD(connmark_listener_t, destroy, void,
	private_connmark_listener_t *this)
{
	free(this);
}

/**
 * See header
 */
connmark_listener_t *connmark_listener_create()
{
	private_connmark_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.ike_update = _ike_update,
				.child_updown = _child_updown,
				.child_rekey = _child_rekey,
			},
			.destroy = _destroy,
		},
	);

	return &this->public;
}
