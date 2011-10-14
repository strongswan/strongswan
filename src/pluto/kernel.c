/* routines that interface with the kernel's IPsec mechanism
 *
 * Copyright (C) 2010 Tobias Brunner
 * Copyright (C) 2009 Andreas Steffen
 * Hochschule fuer Technik Rapperswil
 *
 * Copyright (C) 1998-2002  D. Hugh Redelmeier
 * Copyright (C) 1997 Angelos D. Keromytis
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

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/queue.h>
#include <sys/wait.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <freeswan.h>

#include <library.h>
#include <hydra.h>
#include <crypto/rngs/rng.h>
#include <kernel/kernel_listener.h>

#include <signal.h>
#include <sys/time.h>   /* for select(2) */
#include <sys/types.h>  /* for select(2) */
#include <pfkeyv2.h>
#include <pfkey.h>
#include "kameipsec.h"

#include "constants.h"
#include "defs.h"
#include "connections.h"
#include "state.h"
#include "timer.h"
#include "kernel.h"
#include "kernel_pfkey.h"
#include "log.h"
#include "ca.h"
#include "server.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "keys.h"
#include "crypto.h"
#include "nat_traversal.h"
#include "alg_info.h"
#include "kernel_alg.h"
#include "pluto.h"


bool can_do_IPcomp = TRUE;  /* can system actually perform IPCOMP? */

/* test if the routes required for two different connections agree
 * It is assumed that the destination subnets agree; we are only
 * testing that the interfaces and nexthops match.
 */
#define routes_agree(c, d) ((c)->interface == (d)->interface \
		&& sameaddr(&(c)->spd.this.host_nexthop, &(d)->spd.this.host_nexthop))

/* forward declaration */
static bool shunt_eroute(connection_t *c, struct spd_route *sr,
						 enum routing_t rt_kind, unsigned int op,
						 const char *opname);

static void set_text_said(char *text_said, const ip_address *dst,
						  ipsec_spi_t spi, int proto);

/**
 * Default IPsec SA config (e.g. to install trap policies).
 */
static ipsec_sa_cfg_t null_ipsec_sa = {
	.mode = MODE_TRANSPORT,
	.esp = {
		.use = TRUE,
	},
};

/**
 * Helper function that converts an ip_subnet to a traffic_selector_t.
 */
static traffic_selector_t *traffic_selector_from_subnet(const ip_subnet *client,
														const u_int8_t proto)
{
	traffic_selector_t *ts;
	host_t *net;
	net = host_create_from_sockaddr((sockaddr_t*)&client->addr);
	ts = traffic_selector_create_from_subnet(net, client->maskbits, proto,
											 net->get_port(net));
	return ts;
}

/**
 * Helper function that converts a traffic_selector_t to an ip_subnet.
 */
static ip_subnet subnet_from_traffic_selector(traffic_selector_t *ts)
{
	ip_subnet subnet;
	host_t *net;
	u_int8_t mask;
	ts->to_subnet(ts, &net, &mask);
	subnet.addr = *(ip_address*)net->get_sockaddr(net);
	subnet.maskbits = mask;
	net->destroy(net);
	return subnet;
}


void record_and_initiate_opportunistic(const ip_subnet *ours,
									   const ip_subnet *his,
									   int transport_proto, const char *why)
{
	ip_address src, dst;
	passert(samesubnettype(ours, his));

	/* actually initiate opportunism */
	networkof(ours, &src);
	networkof(his, &dst);
	initiate_opportunistic(&src, &dst, transport_proto, TRUE, NULL_FD);
}

/* Generate Unique SPI numbers.
 *
 * The returned SPI is in network byte order.
 */
ipsec_spi_t get_ipsec_spi(ipsec_spi_t avoid, int proto, struct spd_route *sr,
						  bool tunnel)
{
	host_t *host_src, *host_dst;
	u_int32_t spi;

	host_src = host_create_from_sockaddr((sockaddr_t*)&sr->that.host_addr);
	host_dst = host_create_from_sockaddr((sockaddr_t*)&sr->this.host_addr);

	if (hydra->kernel_interface->get_spi(hydra->kernel_interface, host_src,
								host_dst, proto, sr->reqid, &spi) != SUCCESS)
	{
		spi = 0;
	}

	host_src->destroy(host_src);
	host_dst->destroy(host_dst);

	return spi;
}

/* Generate Unique CPI numbers.
 * The result is returned as an SPI (4 bytes) in network order!
 * The real bits are in the nework-low-order 2 bytes.
 */
ipsec_spi_t get_my_cpi(struct spd_route *sr, bool tunnel)
{
	host_t *host_src, *host_dst;
	u_int16_t cpi;

	host_src = host_create_from_sockaddr((sockaddr_t*)&sr->that.host_addr);
	host_dst = host_create_from_sockaddr((sockaddr_t*)&sr->this.host_addr);

	if (hydra->kernel_interface->get_cpi(hydra->kernel_interface, host_src,
										 host_dst, sr->reqid, &cpi) != SUCCESS)

	{
		cpi = 0;
	}

	host_src->destroy(host_src);
	host_dst->destroy(host_dst);

	return htonl((u_int32_t)ntohs(cpi));
}

/* Replace the shell metacharacters ', \, ", `, and $ in a character string
 * by escape sequences consisting of their octal values
 */
static void escape_metachar(const char *src, char *dst, size_t dstlen)
{
	while (*src != '\0' && dstlen > 4)
	{
		switch (*src)
		{
		case '\'':
		case '\\':
		case '"':
		case '`':
		case '$':
			sprintf(dst,"\\%s%o", (*src < 64)?"0":"", *src);
			dst += 4;
			dstlen -= 4;
			break;
		default:
			*dst++ = *src;
			dstlen--;
		}
		src++;
	}
	*dst = '\0';
}

/* invoke the updown script to do the routing and firewall commands required
 *
 * The user-specified updown script is run.  Parameters are fed to it in
 * the form of environment variables.  All such environment variables
 * have names starting with "PLUTO_".
 *
 * The operation to be performed is specified by PLUTO_VERB.  This
 * verb has a suffix "-host" if the client on this end is just the
 * host; otherwise the suffix is "-client".  If the address family
 * of the host is IPv6, an extra suffix of "-v6" is added.
 *
 * "prepare-host" and "prepare-client" are used to delete a route
 * that may exist (due to forces outside of Pluto).  It is used to
 * prepare for pluto creating a route.
 *
 * "route-host" and "route-client" are used to install a route.
 * Since routing is based only on destination, the PLUTO_MY_CLIENT_*
 * values are probably of no use (using them may signify a bug).
 *
 * "unroute-host" and "unroute-client" are used to delete a route.
 * Since routing is based only on destination, the PLUTO_MY_CLIENT_*
 * values are probably of no use (using them may signify a bug).
 *
 * "up-host" and "up-client" are run when an eroute is added (not replaced).
 * They are useful for adjusting a firewall: usually for adding a rule
 * to let processed packets flow between clients.  Note that only
 * one eroute may exist for a pair of client subnets but inbound
 * IPsec SAs may persist without an eroute.
 *
 * "down-host" and "down-client" are run when an eroute is deleted.
 * They are useful for adjusting a firewall.
 */

#ifndef DEFAULT_UPDOWN
# define DEFAULT_UPDOWN "ipsec _updown"
#endif

static bool do_command(connection_t *c, struct spd_route *sr, struct state *st,
					   const char *verb)
{
	char cmd[1536];     /* arbitrary limit on shell command length */
	const char *verb_suffix;

	/* figure out which verb suffix applies */
	{
		const char *hs, *cs;

		switch (addrtypeof(&sr->this.host_addr))
		{
			case AF_INET:
				hs = "-host";
				cs = "-client";
				break;
			case AF_INET6:
				hs = "-host-v6";
				cs = "-client-v6";
				break;
			default:
				loglog(RC_LOG_SERIOUS, "unknown address family");
				return FALSE;
		}
		verb_suffix = subnetisaddr(&sr->this.client, &sr->this.host_addr)
			? hs : cs;
	}

	/* form the command string */
	{
		char
			nexthop_str[sizeof("PLUTO_NEXT_HOP='' ") +ADDRTOT_BUF] = "",
			srcip_str[sizeof("PLUTO_MY_SOURCEIP='' ")+ADDRTOT_BUF] = "",
			me_str[ADDRTOT_BUF],
			myid_str[BUF_LEN],
			myclient_str[SUBNETTOT_BUF],
			myclientnet_str[ADDRTOT_BUF],
			myclientmask_str[ADDRTOT_BUF],
			peer_str[ADDRTOT_BUF],
			peerid_str[BUF_LEN],
			peerclient_str[SUBNETTOT_BUF],
			peerclientnet_str[ADDRTOT_BUF],
			peerclientmask_str[ADDRTOT_BUF],
			peerca_str[BUF_LEN],
			mark_in[BUF_LEN] = "",
			mark_out[BUF_LEN] = "",
			udp_encap[BUF_LEN] = "",
			xauth_id_str[BUF_LEN] = "",
			secure_myid_str[BUF_LEN] = "",
			secure_peerid_str[BUF_LEN] = "",
			secure_peerca_str[BUF_LEN] = "",
			secure_xauth_id_str[BUF_LEN] = "";
		ip_address ta;
		pubkey_list_t *p;

		if (addrbytesptr(&sr->this.host_nexthop, NULL)
		&& !isanyaddr(&sr->this.host_nexthop))
		{
			char *n;

			strcpy(nexthop_str, "PLUTO_NEXT_HOP='");
			n = nexthop_str + strlen(nexthop_str);

			addrtot(&sr->this.host_nexthop, 0
					,n , sizeof(nexthop_str)-strlen(nexthop_str));
			strncat(nexthop_str, "' ", sizeof(nexthop_str));
		}

		if (!sr->this.host_srcip->is_anyaddr(sr->this.host_srcip))
		{
			char *n;

			strcpy(srcip_str, "PLUTO_MY_SOURCEIP='");
			n = srcip_str + strlen(srcip_str);
			snprintf(n, sizeof(srcip_str)-strlen(srcip_str), "%H",
						sr->this.host_srcip);
			strncat(srcip_str, "' ", sizeof(srcip_str));
		}

		if (sr->mark_in.value)
		{
			snprintf(mark_in, sizeof(mark_in), "PLUTO_MARK_IN='%u/0x%08x' ",
					 sr->mark_in.value, sr->mark_in.mask);
		}

		if (sr->mark_out.value)
		{
			snprintf(mark_out, sizeof(mark_out), "PLUTO_MARK_OUT='%u/0x%08x' ",
					 sr->mark_out.value, sr->mark_out.mask);
		}

		if (st && (st->nat_traversal & NAT_T_DETECTED))
		{
			snprintf(udp_encap, sizeof(udp_encap), "PLUTO_UDP_ENC='%u' ",
					 sr->that.host_port);
		}

		addrtot(&sr->this.host_addr, 0, me_str, sizeof(me_str));
		snprintf(myid_str, sizeof(myid_str), "%Y", sr->this.id);
		escape_metachar(myid_str, secure_myid_str, sizeof(secure_myid_str));
		subnettot(&sr->this.client, 0, myclient_str, sizeof(myclientnet_str));
		networkof(&sr->this.client, &ta);
		addrtot(&ta, 0, myclientnet_str, sizeof(myclientnet_str));
		maskof(&sr->this.client, &ta);
		addrtot(&ta, 0, myclientmask_str, sizeof(myclientmask_str));

		if (c->xauth_identity &&
			c->xauth_identity->get_type(c->xauth_identity) != ID_ANY)
		{
			snprintf(xauth_id_str, sizeof(xauth_id_str), "%Y", c->xauth_identity);
			escape_metachar(xauth_id_str, secure_xauth_id_str,
					 sizeof(secure_xauth_id_str));
			snprintf(xauth_id_str, sizeof(xauth_id_str), "PLUTO_XAUTH_ID='%s' ",
					 secure_xauth_id_str);
		}

		addrtot(&sr->that.host_addr, 0, peer_str, sizeof(peer_str));
		snprintf(peerid_str, sizeof(peerid_str), "%Y", sr->that.id);
		escape_metachar(peerid_str, secure_peerid_str, sizeof(secure_peerid_str));
		subnettot(&sr->that.client, 0, peerclient_str, sizeof(peerclientnet_str));
		networkof(&sr->that.client, &ta);
		addrtot(&ta, 0, peerclientnet_str, sizeof(peerclientnet_str));
		maskof(&sr->that.client, &ta);
		addrtot(&ta, 0, peerclientmask_str, sizeof(peerclientmask_str));

		for (p = pubkeys; p != NULL; p = p->next)
		{
			pubkey_t *key = p->key;
			key_type_t type = key->public_key->get_type(key->public_key);
			int pathlen;

			if (type == KEY_RSA &&
				sr->that.id->equals(sr->that.id, key->id) &&
				trusted_ca(key->issuer, sr->that.ca, &pathlen))
			{
				if (key->issuer)
				{
					snprintf(peerca_str, BUF_LEN, "%Y", key->issuer);
					escape_metachar(peerca_str, secure_peerca_str, BUF_LEN);
				}
				else
				{
					secure_peerca_str[0] = '\0';
				}
				break;
			}
		}

		if (-1 == snprintf(cmd, sizeof(cmd)
			, "2>&1 "   /* capture stderr along with stdout */
			"PLUTO_VERSION='1.1' "      /* change VERSION when interface spec changes */
			"PLUTO_VERB='%s%s' "
			"PLUTO_CONNECTION='%s' "
			"%s"        /* optional PLUTO_NEXT_HOP */
			"PLUTO_INTERFACE='%s' "
			"%s"        /* optional PLUTO_HOST_ACCESS */
			"PLUTO_REQID='%u' "
			"PLUTO_ME='%s' "
			"PLUTO_MY_ID='%s' "
			"PLUTO_MY_CLIENT='%s' "
			"PLUTO_MY_CLIENT_NET='%s' "
			"PLUTO_MY_CLIENT_MASK='%s' "
			"PLUTO_MY_PORT='%u' "
			"PLUTO_MY_PROTOCOL='%u' "
			"PLUTO_PEER='%s' "
			"PLUTO_PEER_ID='%s' "
			"PLUTO_PEER_CLIENT='%s' "
			"PLUTO_PEER_CLIENT_NET='%s' "
			"PLUTO_PEER_CLIENT_MASK='%s' "
			"PLUTO_PEER_PORT='%u' "
			"PLUTO_PEER_PROTOCOL='%u' "
			"PLUTO_PEER_CA='%s' "
			"%s"        /* optional PLUTO_MY_SRCIP */
			"%s"        /* optional PLUTO_XAUTH_ID */
			"%s"        /* optional PLUTO_MARK_IN */
			"%s"        /* optional PLUTO_MARK_OUT */
			"%s"        /* optional PLUTO_UDP_ENC */
			"%s"        /* actual script */
			, verb, verb_suffix
			, c->name
			, nexthop_str
			, c->interface->vname
			, sr->this.hostaccess? "PLUTO_HOST_ACCESS='1' " : ""
			, sr->reqid
			, me_str
			, secure_myid_str
			, myclient_str
			, myclientnet_str
			, myclientmask_str
			, sr->this.port
			, sr->this.protocol
			, peer_str
			, secure_peerid_str
			, peerclient_str
			, peerclientnet_str
			, peerclientmask_str
			, sr->that.port
			, sr->that.protocol
			, secure_peerca_str
			, srcip_str
			, xauth_id_str
			, mark_in
			, mark_out
			, udp_encap
			, sr->this.updown == NULL? DEFAULT_UPDOWN : sr->this.updown))
		{
			loglog(RC_LOG_SERIOUS, "%s%s command too long!", verb, verb_suffix);
			return FALSE;
		}
	}

	DBG(DBG_CONTROL, DBG_log("executing %s%s: %s"
		, verb, verb_suffix, cmd));

	/* invoke the script, catching stderr and stdout
	 * It may be of concern that some file descriptors will
	 * be inherited.  For the ones under our control, we
	 * have done fcntl(fd, F_SETFD, FD_CLOEXEC) to prevent this.
	 * Any used by library routines (perhaps the resolver or syslog)
	 * will remain.
	 */
	FILE *f = popen(cmd, "r");

	if (f == NULL)
	{
		loglog(RC_LOG_SERIOUS, "unable to popen %s%s command", verb, verb_suffix);
		return FALSE;
	}

	/* log any output */
	for (;;)
	{
		/* if response doesn't fit in this buffer, it will be folded */
		char resp[256];

		if (fgets(resp, sizeof(resp), f) == NULL)
		{
			if (ferror(f))
			{
				log_errno((e, "fgets failed on output of %s%s command"
					, verb, verb_suffix));
				return FALSE;
			}
			else
			{
				passert(feof(f));
				break;
			}
		}
		else
		{
			char *e = resp + strlen(resp);

			if (e > resp && e[-1] == '\n')
				e[-1] = '\0';       /* trim trailing '\n' */
			plog("%s%s output: %s", verb, verb_suffix, resp);
		}
	}

	/* report on and react to return code */
	{
		int r = pclose(f);

		if (r == -1)
		{
			log_errno((e, "pclose failed for %s%s command"
				, verb, verb_suffix));
			return FALSE;
		}
		else if (WIFEXITED(r))
		{
			if (WEXITSTATUS(r) != 0)
			{
				loglog(RC_LOG_SERIOUS, "%s%s command exited with status %d"
					, verb, verb_suffix, WEXITSTATUS(r));
				return FALSE;
			}
		}
		else if (WIFSIGNALED(r))
		{
			loglog(RC_LOG_SERIOUS, "%s%s command exited with signal %d"
				, verb, verb_suffix, WTERMSIG(r));
			return FALSE;
		}
		else
		{
			loglog(RC_LOG_SERIOUS, "%s%s command exited with unknown status %d"
				, verb, verb_suffix, r);
			return FALSE;
		}
	}
	return TRUE;
}

/* Check that we can route (and eroute).  Diagnose if we cannot. */

enum routability {
	route_impossible = 0,
	route_easy = 1,
	route_nearconflict = 2,
	route_farconflict = 3
};

static enum routability could_route(connection_t *c)
{
	struct spd_route *esr, *rosr;
	connection_t *ero      /* who, if anyone, owns our eroute? */
		, *ro = route_owner(c, &rosr, &ero, &esr); /* who owns our route? */

	/* it makes no sense to route a connection that is ISAKMP-only */
	if (!NEVER_NEGOTIATE(c->policy) && !HAS_IPSEC_POLICY(c->policy))
	{
		loglog(RC_ROUTE, "cannot route an ISAKMP-only connection");
		return route_impossible;
	}

	/* if this is a Road Warrior template, we cannot route.
	 * Opportunistic template is OK.
	 */
	if (c->kind == CK_TEMPLATE && !(c->policy & POLICY_OPPO))
	{
		loglog(RC_ROUTE, "cannot route Road Warrior template");
		return route_impossible;
	}

	/* if we don't know nexthop, we cannot route */
	if (isanyaddr(&c->spd.this.host_nexthop))
	{
		loglog(RC_ROUTE, "cannot route connection without knowing our nexthop");
		return route_impossible;
	}

	/* if routing would affect IKE messages, reject */
	if (c->spd.this.host_port != NAT_T_IKE_FLOAT_PORT
	 && c->spd.this.host_port != IKE_UDP_PORT
	 && addrinsubnet(&c->spd.that.host_addr, &c->spd.that.client))
	{
		loglog(RC_LOG_SERIOUS, "cannot install route: peer is within its client");
		return route_impossible;
	}

	/* If there is already a route for peer's client subnet
	 * and it disagrees about interface or nexthop, we cannot steal it.
	 * Note: if this connection is already routed (perhaps for another
	 * state object), the route will agree.
	 * This is as it should be -- it will arise during rekeying.
	 */
	if (ro != NULL && !routes_agree(ro, c))
	{
		loglog(RC_LOG_SERIOUS, "cannot route -- route already in use for \"%s\""
			, ro->name);
		return route_impossible;  /* another connection already
									 using the eroute */
	}

	/* if there is an eroute for another connection, there is a problem */
	if (ero != NULL && ero != c)
	{
		connection_t *ero2, *ero_top;
		connection_t *inside, *outside;

		/*
		 * note, wavesec (PERMANENT) goes *outside* and
		 * OE goes *inside* (TEMPLATE)
		 */
		inside = NULL;
		outside= NULL;
		if (ero->kind == CK_PERMANENT
		   && c->kind == CK_TEMPLATE)
		{
			outside = ero;
			inside = c;
		}
		else if (c->kind == CK_PERMANENT
				&& ero->kind == CK_TEMPLATE)
		{
			outside = c;
			inside = ero;
		}

		/* okay, check again, with correct order */
		if (outside && outside->kind == CK_PERMANENT
			&& inside && inside->kind == CK_TEMPLATE)
		{
			char inst[CONN_INST_BUF];

			/* this is a co-terminal attempt of the "near" kind. */
			/* when chaining, we chain from inside to outside */

			/* XXX permit multiple deep connections? */
			passert(inside->policy_next == NULL);

			inside->policy_next = outside;

			/* since we are going to steal the eroute from the secondary
			 * policy, we need to make sure that it no longer thinks that
			 * it owns the eroute.
			 */
			outside->spd.eroute_owner = SOS_NOBODY;
			outside->spd.routing = RT_UNROUTED_KEYED;

			/* set the priority of the new eroute owner to be higher
			 * than that of the current eroute owner
			 */
			inside->prio = outside->prio + 1;

			fmt_conn_instance(inside, inst);

			loglog(RC_LOG_SERIOUS
				   , "conflict on eroute (%s), switching eroute to %s and linking %s"
				   , inst, inside->name, outside->name);

			return route_nearconflict;
		}

		/* look along the chain of policies for one with the same name */
		ero_top = ero;

		for (ero2 = ero; ero2 != NULL; ero2 = ero->policy_next)
		{
			if (ero2->kind == CK_TEMPLATE
			&& streq(ero2->name, c->name))
				break;
		}

		/* If we fell of the end of the list, then we found no TEMPLATE
		 * so there must be a conflict that we can't resolve.
		 * As the names are not equal, then we aren't replacing/rekeying.
		 */
		if (ero2 == NULL)
		{
			char inst[CONN_INST_BUF];

			fmt_conn_instance(ero, inst);

			loglog(RC_LOG_SERIOUS
				, "cannot install eroute -- it is in use for \"%s\"%s #%lu"
				, ero->name, inst, esr->eroute_owner);
			return route_impossible;
		}
	}
	return route_easy;
}

bool trap_connection(connection_t *c)
{
	switch (could_route(c))
	{
	case route_impossible:
		return FALSE;

	case route_nearconflict:
	case route_easy:
		/* RT_ROUTED_TUNNEL is treated specially: we don't override
		 * because we don't want to lose track of the IPSEC_SAs etc.
		 */
		if (c->spd.routing < RT_ROUTED_TUNNEL)
		{
			return route_and_eroute(c, &c->spd, NULL);
		}
		return TRUE;

	case route_farconflict:
		return FALSE;
	}

	return FALSE;
}

/**
 * Delete any eroute for a connection and unroute it if route isn't shared
 */
void unroute_connection(connection_t *c)
{
	struct spd_route *sr;
	enum routing_t cr;

	for (sr = &c->spd; sr; sr = sr->next)
	{
		cr = sr->routing;

		if (erouted(cr))
		{
			/* cannot handle a live one */
			passert(sr->routing != RT_ROUTED_TUNNEL);
			shunt_eroute(c, sr, RT_UNROUTED, ERO_DELETE, "delete");
		}

		sr->routing = RT_UNROUTED;  /* do now so route_owner won't find us */

		/* only unroute if no other connection shares it */
		if (routed(cr) && route_owner(c, NULL, NULL, NULL) == NULL)
		{
			(void) do_command(c, sr, NULL, "unroute");
		}
	}
}


static void set_text_said(char *text_said, const ip_address *dst,
						  ipsec_spi_t spi, int proto)
{
	ip_said said;

	initsaid(dst, spi, proto, &said);
	satot(&said, 0, text_said, SATOT_BUF);
}


/**
 * Setup an IPsec route entry.
 * op is one of the ERO_* operators.
 */
static bool raw_eroute(const ip_address *this_host,
					   const ip_subnet *this_client,
					   const ip_address *that_host,
					   const ip_subnet *that_client,
					   mark_t mark,
					   ipsec_spi_t spi,
					   unsigned int proto,
					   unsigned int satype,
					   unsigned int transport_proto,
					   ipsec_sa_cfg_t *sa,
					   unsigned int op,
					   const char *opname USED_BY_DEBUG)
{
	traffic_selector_t *ts_src, *ts_dst;
	host_t *host_src, *host_dst;
	policy_type_t type = POLICY_IPSEC;
	policy_dir_t dir = POLICY_OUT;
	policy_priority_t priority = POLICY_PRIORITY_DEFAULT;
	char text_said[SATOT_BUF];
	bool ok = TRUE,
		 deleting = (op & ERO_MASK) == ERO_DELETE,
		 replacing = op & (SADB_X_SAFLAGS_REPLACEFLOW << ERO_FLAG_SHIFT);

	set_text_said(text_said, that_host, spi, proto);

	DBG(DBG_CONTROL | DBG_KERNEL,
		{
			int sport = ntohs(portof(&this_client->addr));
			int dport = ntohs(portof(&that_client->addr));
			char mybuf[SUBNETTOT_BUF];
			char peerbuf[SUBNETTOT_BUF];

			subnettot(this_client, 0, mybuf, sizeof(mybuf));
			subnettot(that_client, 0, peerbuf, sizeof(peerbuf));
			DBG_log("%s eroute %s:%d -> %s:%d => %s:%d"
				, opname, mybuf, sport, peerbuf, dport
				, text_said, transport_proto);
		});

	if (satype == SADB_X_SATYPE_INT)
	{
		switch (ntohl(spi))
		{
			case SPI_PASS:
				type = POLICY_PASS;
				break;
			case SPI_DROP:
			case SPI_REJECT:
				type = POLICY_DROP;
				break;
			case SPI_TRAP:
			case SPI_TRAPSUBNET:
			case SPI_HOLD:
				if (op & (SADB_X_SAFLAGS_INFLOW << ERO_FLAG_SHIFT))
				{
					return TRUE;
				}
				priority = POLICY_PRIORITY_ROUTED;
				break;
		}
	}

	if (op & (SADB_X_SAFLAGS_INFLOW << ERO_FLAG_SHIFT))
	{
		dir = POLICY_IN;
	}

	host_src = host_create_from_sockaddr((sockaddr_t*)this_host);
	host_dst = host_create_from_sockaddr((sockaddr_t*)that_host);
	ts_src = traffic_selector_from_subnet(this_client, transport_proto);
	ts_dst = traffic_selector_from_subnet(that_client, transport_proto);

	if (deleting || replacing)
	{
		hydra->kernel_interface->del_policy(hydra->kernel_interface,
						ts_src, ts_dst, dir, sa->reqid, mark, priority);
	}

	if (!deleting)
	{
		ok = hydra->kernel_interface->add_policy(hydra->kernel_interface,
						host_src, host_dst, ts_src, ts_dst, dir, type, sa,
						mark, priority) == SUCCESS;
	}

	if (dir == POLICY_IN)
	{	/* handle forward policy */
		dir = POLICY_FWD;
		if (deleting || replacing)
		{
			hydra->kernel_interface->del_policy(hydra->kernel_interface,
						ts_src, ts_dst, dir, sa->reqid, mark, priority);
		}

		if (!deleting && ok &&
			(sa->mode == MODE_TUNNEL || satype == SADB_X_SATYPE_INT))
		{
			ok = hydra->kernel_interface->add_policy(hydra->kernel_interface,
						host_src, host_dst, ts_src, ts_dst, dir, type, sa,
						mark, priority) == SUCCESS;
		}
	}

	host_src->destroy(host_src);
	host_dst->destroy(host_dst);
	ts_src->destroy(ts_src);
	ts_dst->destroy(ts_dst);

	return ok;
}

static bool eroute_connection(struct spd_route *sr, ipsec_spi_t spi,
							  unsigned int proto, unsigned int satype,
							  ipsec_sa_cfg_t *sa, unsigned int op,
							  const char *opname)
{
	const ip_address *peer = &sr->that.host_addr;
	char buf2[256];
	bool ok;

	snprintf(buf2, sizeof(buf2)
			 , "eroute_connection %s", opname);

	if (proto == SA_INT)
	{
		peer = aftoinfo(addrtypeof(peer))->any;
	}
	ok = raw_eroute(peer, &sr->that.client,
					&sr->this.host_addr, &sr->this.client, sr->mark_in,
					spi, proto, satype, sr->this.protocol,
					sa, op | (SADB_X_SAFLAGS_INFLOW << ERO_FLAG_SHIFT), buf2);
	return raw_eroute(&sr->this.host_addr, &sr->this.client, peer,
					  &sr->that.client, sr->mark_out, spi, proto, satype,
					  sr->this.protocol, sa, op, buf2) && ok;
}

/* assign a bare hold to a connection */

bool assign_hold(connection_t *c USED_BY_DEBUG, struct spd_route *sr,
				 int transport_proto,
				 const ip_address *src,
				 const ip_address *dst)
{
	/* either the automatically installed %hold eroute is broad enough
	 * or we try to add a broader one and delete the automatic one.
	 * Beware: this %hold might be already handled, but still squeak
	 * through because of a race.
	 */
	enum routing_t ro = sr->routing     /* routing, old */
		, rn = ro;                      /* routing, new */

	passert(LHAS(LELEM(CK_PERMANENT) | LELEM(CK_INSTANCE), c->kind));
	/* figure out what routing should become */
	switch (ro)
	{
	case RT_UNROUTED:
		rn = RT_UNROUTED_HOLD;
		break;
	case RT_ROUTED_PROSPECTIVE:
		rn = RT_ROUTED_HOLD;
		break;
	default:
		/* no change: this %hold is old news and should just be deleted */
		break;
	}

	/* We need a broad %hold
	 * First we ensure that there is a broad %hold.
	 * There may already be one (race condition): no need to create one.
	 * There may already be a %trap: replace it.
	 * There may not be any broad eroute: add %hold.
	 */
	if (rn != ro)
	{
		if (erouted(ro)
		? !eroute_connection(sr, htonl(SPI_HOLD), SA_INT, SADB_X_SATYPE_INT,
							 &null_ipsec_sa, ERO_REPLACE,
							 "replace %trap with broad %hold")
		: !eroute_connection(sr, htonl(SPI_HOLD), SA_INT, SADB_X_SATYPE_INT,
							 &null_ipsec_sa, ERO_ADD, "add broad %hold"))
		{
			return FALSE;
		}
	}
	sr->routing = rn;
	return TRUE;
}

/* install or remove eroute for SA Group */
static bool sag_eroute(struct state *st, struct spd_route *sr,
					   unsigned op, const char *opname)
{
	u_int inner_proto, inner_satype;
	ipsec_spi_t inner_spi = 0;
	ipsec_sa_cfg_t sa = {
		.mode = MODE_TRANSPORT,
	};
	bool tunnel = FALSE;

	if (st->st_ah.present)
	{
		inner_spi = st->st_ah.attrs.spi;
		inner_proto = SA_AH;
		inner_satype = SADB_SATYPE_AH;
		sa.ah.use = TRUE;
		sa.ah.spi = inner_spi;
		tunnel |= st->st_ah.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL;
	}

	if (st->st_esp.present)
	{
		inner_spi = st->st_esp.attrs.spi;
		inner_proto = SA_ESP;
		inner_satype = SADB_SATYPE_ESP;
		sa.esp.use = TRUE;
		sa.esp.spi = inner_spi;
		tunnel |= st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL;
	}

	if (st->st_ipcomp.present)
	{
		inner_spi = st->st_ipcomp.attrs.spi;
		inner_proto = SA_COMP;
		inner_satype = SADB_X_SATYPE_COMP;
		sa.ipcomp.transform = st->st_ipcomp.attrs.transid;
		sa.ipcomp.cpi = htons(ntohl(inner_spi));
		tunnel |= st->st_ipcomp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL;
	}

	if (!sa.ah.use && !sa.esp.use && !sa.ipcomp.transform)
	{
		impossible();   /* no transform at all! */
	}

	if (tunnel)
	{
		inner_spi = st->st_tunnel_out_spi;
		inner_proto = SA_IPIP;
		inner_satype = SADB_X_SATYPE_IPIP;
		sa.mode = MODE_TUNNEL;
	}

	sa.reqid = sr->reqid;

	return eroute_connection(sr, inner_spi, inner_proto, inner_satype,
							 &sa, op, opname);
}

/* compute a (host-order!) SPI to implement the policy in connection c */
ipsec_spi_t
shunt_policy_spi(connection_t *c, bool prospective)
{
	/* note: these are in host order :-( */
	static const ipsec_spi_t shunt_spi[] =
	{
		SPI_TRAP,       /* --initiateontraffic */
		SPI_PASS,       /* --pass */
		SPI_DROP,       /* --drop */
		SPI_REJECT,     /* --reject */
	};

	static const ipsec_spi_t fail_spi[] =
	{
		0,      /* --none*/
		SPI_PASS,       /* --failpass */
		SPI_DROP,       /* --faildrop */
		SPI_REJECT,     /* --failreject */
	};

	return prospective
		? shunt_spi[(c->policy & POLICY_SHUNT_MASK) >> POLICY_SHUNT_SHIFT]
		: fail_spi[(c->policy & POLICY_FAIL_MASK) >> POLICY_FAIL_SHIFT];
}

/* Add/replace/delete a shunt eroute.
 * Such an eroute determines the fate of packets without the use
 * of any SAs.  These are defaults, in effect.
 * If a negotiation has not been attempted, use %trap.
 * If negotiation has failed, the choice between %trap/%pass/%drop/%reject
 * is specified in the policy of connection c.
 */
static bool shunt_eroute(connection_t *c, struct spd_route *sr,
						 enum routing_t rt_kind,
						 unsigned int op, const char *opname)
{
	/* We are constructing a special SAID for the eroute.
	 * The destination doesn't seem to matter, but the family does.
	 * The protocol is SA_INT -- mark this as shunt.
	 * The satype has no meaning, but is required for PF_KEY header!
	 * The SPI signifies the kind of shunt.
	 */
	ipsec_spi_t spi = shunt_policy_spi(c, rt_kind == RT_ROUTED_PROSPECTIVE);

	if (spi == 0)
	{
		/* we're supposed to end up with no eroute: rejig op and opname */
		switch (op)
		{
		case ERO_REPLACE:
			/* replace with nothing == delete */
			op = ERO_DELETE;
			opname = "delete";
			break;
		case ERO_ADD:
			/* add nothing == do nothing */
			return TRUE;
		case ERO_DELETE:
			/* delete remains delete */
			break;
		default:
			bad_case(op);
		}
	}
	if (sr->routing == RT_ROUTED_ECLIPSED && c->kind == CK_TEMPLATE)
	{
		/* We think that we have an eroute, but we don't.
		 * Adjust the request and account for eclipses.
		 */
		passert(eclipsable(sr));
		switch (op)
		{
		case ERO_REPLACE:
			/* really an add */
			op = ERO_ADD;
			opname = "replace eclipsed";
			eclipse_count--;
			break;
		case ERO_DELETE:
			/* delete unnecessary: we don't actually have an eroute */
			eclipse_count--;
			return TRUE;
		case ERO_ADD:
		default:
			bad_case(op);
		}
	}
	else if (eclipse_count > 0 && op == ERO_DELETE && eclipsable(sr))
	{
		/* maybe we are uneclipsing something */
		struct spd_route *esr;
		connection_t *ue = eclipsed(c, &esr);

		if (ue != NULL)
		{
			esr->routing = RT_ROUTED_PROSPECTIVE;
			return shunt_eroute(ue, esr
								, RT_ROUTED_PROSPECTIVE, ERO_REPLACE, "restoring eclipsed");
		}
	}

	return eroute_connection(sr, htonl(spi), SA_INT, SADB_X_SATYPE_INT,
							 &null_ipsec_sa, op, opname);
}

static bool setup_half_ipsec_sa(struct state *st, bool inbound)
{
	host_t *host_src, *host_dst;
	connection_t *c = st->st_connection;
	struct end *src, *dst;
	ipsec_mode_t mode = MODE_TRANSPORT;
	ipsec_sa_cfg_t sa = { .mode = 0 };
	lifetime_cfg_t lt_none = { .time = { .rekey = 0 } };
	mark_t mark;
	bool ok = TRUE;
	/* SPIs, saved for undoing, if necessary */
	struct kernel_sa said[EM_MAXRELSPIS], *said_next = said;
	if (inbound)
	{
		src = &c->spd.that;
		dst = &c->spd.this;
		mark = c->spd.mark_in;
	}
	else
	{
		src = &c->spd.this;
		dst = &c->spd.that;
		mark = c->spd.mark_out;
	}

	host_src = host_create_from_sockaddr((sockaddr_t*)&src->host_addr);
	host_dst = host_create_from_sockaddr((sockaddr_t*)&dst->host_addr);

	if (st->st_ah.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL
		|| st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL
		|| st->st_ipcomp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
	{
		mode = MODE_TUNNEL;
	}

	sa.mode = mode;
	sa.reqid = c->spd.reqid;

	memset(said, 0, sizeof(said));

	/* set up IPCOMP SA, if any */

	if (st->st_ipcomp.present)
	{
		ipsec_spi_t ipcomp_spi = inbound ? st->st_ipcomp.our_spi
										 : st->st_ipcomp.attrs.spi;

		switch (st->st_ipcomp.attrs.transid)
		{
			case IPCOMP_DEFLATE:
				break;

			default:
				loglog(RC_LOG_SERIOUS, "IPCOMP transform %s not implemented",
					   enum_name(&ipcomp_transformid_names,
								 st->st_ipcomp.attrs.transid));
				goto fail;
		}

		sa.ipcomp.cpi = htons(ntohl(ipcomp_spi));
		sa.ipcomp.transform = st->st_ipcomp.attrs.transid;

		said_next->spi = ipcomp_spi;
		said_next->proto = IPPROTO_COMP;

		if (hydra->kernel_interface->add_sa(hydra->kernel_interface, host_src,
						host_dst, ipcomp_spi, said_next->proto, c->spd.reqid,
						mark, 0, &lt_none, ENCR_UNDEFINED, chunk_empty,
						AUTH_UNDEFINED, chunk_empty, mode,
						st->st_ipcomp.attrs.transid, 0 /* cpi */, FALSE, FALSE,
						inbound, NULL, NULL) != SUCCESS)
		{
			goto fail;
		}
		said_next++;
		mode = MODE_TRANSPORT;
	}

	/* set up ESP SA, if any */

	if (st->st_esp.present)
	{
		ipsec_spi_t esp_spi = inbound ? st->st_esp.our_spi
									  : st->st_esp.attrs.spi;
		u_char *esp_dst_keymat = inbound ? st->st_esp.our_keymat
										 : st->st_esp.peer_keymat;
		bool encap = st->nat_traversal & NAT_T_DETECTED;
		encryption_algorithm_t enc_alg;
		integrity_algorithm_t auth_alg;
		const struct esp_info *ei;
		chunk_t enc_key, auth_key;
		u_int16_t key_len;

		if ((ei = kernel_alg_esp_info(st->st_esp.attrs.transid,
									  st->st_esp.attrs.auth)) == NULL)
		{
			loglog(RC_LOG_SERIOUS, "ESP transform %s / auth %s"
				   " not implemented yet",
				   enum_name(&esp_transform_names, st->st_esp.attrs.transid),
				   enum_name(&auth_alg_names, st->st_esp.attrs.auth));
			goto fail;
		}

		key_len = st->st_esp.attrs.key_len / 8;
		if (key_len)
		{
			/* XXX: must change to check valid _range_ key_len */
			if (key_len > ei->enckeylen)
			{
				loglog(RC_LOG_SERIOUS, "ESP transform %s: key_len=%d > %d",
					enum_name(&esp_transform_names, st->st_esp.attrs.transid),
					(int)key_len, (int)ei->enckeylen);
				goto fail;
			}
		}
		else
		{
			key_len = ei->enckeylen;
		}

		switch (ei->transid)
		{
			case ESP_3DES:
				/* 168 bits in kernel, need 192 bits for keymat_len */
				if (key_len == 21)
				{
					key_len = 24;
				}
				break;
			case ESP_DES:
				/* 56 bits in kernel, need 64 bits for keymat_len */
				if (key_len == 7)
				{
					key_len = 8;
				}
				break;
			case ESP_AES_CCM_8:
			case ESP_AES_CCM_12:
			case ESP_AES_CCM_16:
				key_len += 3;
				break;
			case ESP_AES_GCM_8:
			case ESP_AES_GCM_12:
			case ESP_AES_GCM_16:
			case ESP_AES_CTR:
			case ESP_AES_GMAC:
				key_len += 4;
				break;
			default:
				break;
		}

		if (encap)
		{
			host_src->set_port(host_src, src->host_port);
			host_dst->set_port(host_dst, dst->host_port);
			// st->nat_oa is currently unused
		}

		/* divide up keying material */
		enc_alg = encryption_algorithm_from_esp(st->st_esp.attrs.transid);
		enc_key.ptr = esp_dst_keymat;
		enc_key.len = key_len;
		auth_alg = integrity_algorithm_from_esp(st->st_esp.attrs.auth);
		auth_alg = auth_alg ? : AUTH_UNDEFINED;
		auth_key.ptr = esp_dst_keymat + key_len;
		auth_key.len = ei->authkeylen;

		sa.esp.use = TRUE;
		sa.esp.spi = esp_spi;

		said_next->spi = esp_spi;
		said_next->proto = IPPROTO_ESP;

		if (hydra->kernel_interface->add_sa(hydra->kernel_interface, host_src,
						host_dst, esp_spi, said_next->proto, c->spd.reqid,
						mark, 0, &lt_none, enc_alg, enc_key,
						auth_alg, auth_key, mode, IPCOMP_NONE, 0 /* cpi */,
						encap, FALSE, inbound, NULL, NULL) != SUCCESS)
		{
			goto fail;
		}
		said_next++;
		mode = MODE_TRANSPORT;
	}

	/* set up AH SA, if any */

	if (st->st_ah.present)
	{
		ipsec_spi_t ah_spi = inbound ? st->st_ah.our_spi
									 : st->st_ah.attrs.spi;
		u_char *ah_dst_keymat = inbound ? st->st_ah.our_keymat
										: st->st_ah.peer_keymat;
		integrity_algorithm_t auth_alg;
		chunk_t auth_key;

		auth_alg = integrity_algorithm_from_esp(st->st_ah.attrs.auth);
		auth_key.ptr = ah_dst_keymat;
		auth_key.len = st->st_ah.keymat_len;

		sa.ah.use = TRUE;
		sa.ah.spi = ah_spi;

		said_next->spi = ah_spi;
		said_next->proto = IPPROTO_AH;

		if (hydra->kernel_interface->add_sa(hydra->kernel_interface, host_src,
						host_dst, ah_spi, said_next->proto, c->spd.reqid,
						mark, 0, &lt_none, ENCR_UNDEFINED, chunk_empty,
						auth_alg, auth_key, mode, IPCOMP_NONE, 0 /* cpi */,
						FALSE, FALSE, inbound, NULL, NULL) != SUCCESS)
		{
			goto fail;
		}
		said_next++;
		mode = MODE_TRANSPORT;
	}

	goto cleanup;

fail:
	/* undo the done SPIs */
	while (said_next-- != said)
	{
		hydra->kernel_interface->del_sa(hydra->kernel_interface, host_src,
										host_dst, said_next->spi,
										said_next->proto, 0 /* cpi */,
										mark);
	}
	ok = FALSE;

cleanup:
	host_src->destroy(host_src);
	host_dst->destroy(host_dst);
	return ok;
}

static bool teardown_half_ipsec_sa(struct state *st, bool inbound)
{
	connection_t *c = st->st_connection;
	const struct end *src, *dst;
	host_t *host_src, *host_dst;
	ipsec_spi_t spi;
	mark_t mark;
	bool result = TRUE;

	if (inbound)
	{
		src = &c->spd.that;
		dst = &c->spd.this;
		mark = c->spd.mark_in;
	}
	else
	{
		src = &c->spd.this;
		dst = &c->spd.that;
		mark = c->spd.mark_out;
	}

	host_src = host_create_from_sockaddr((sockaddr_t*)&src->host_addr);
	host_dst = host_create_from_sockaddr((sockaddr_t*)&dst->host_addr);

	if (st->st_ah.present)
	{
		spi = inbound ? st->st_ah.our_spi : st->st_ah.attrs.spi;
		result &= hydra->kernel_interface->del_sa(hydra->kernel_interface,
								host_src, host_dst, spi, IPPROTO_AH,
								0 /* cpi */, mark) == SUCCESS;
	}

	if (st->st_esp.present)
	{
		spi = inbound ? st->st_esp.our_spi : st->st_esp.attrs.spi;
		result &= hydra->kernel_interface->del_sa(hydra->kernel_interface,
								host_src, host_dst, spi, IPPROTO_ESP,
								0 /* cpi */, mark) == SUCCESS;
	}

	if (st->st_ipcomp.present)
	{
		spi = inbound ? st->st_ipcomp.our_spi : st->st_ipcomp.attrs.spi;
		result &= hydra->kernel_interface->del_sa(hydra->kernel_interface,
								host_src, host_dst, spi, IPPROTO_COMP,
								0 /* cpi */, mark) == SUCCESS;
	}

	host_src->destroy(host_src);
	host_dst->destroy(host_dst);

	return result;
}

/*
 * get information about a given sa
 */
bool get_sa_info(struct state *st, bool inbound, u_int *bytes, time_t *use_time)
{
	connection_t *c = st->st_connection;
	traffic_selector_t *ts_src = NULL, *ts_dst = NULL;
	host_t *host_src = NULL, *host_dst = NULL;
	const struct end *src, *dst;
	ipsec_spi_t spi;
	mark_t mark;
	u_int64_t bytes_kernel = 0;
	bool result = FALSE;

	*use_time = UNDEFINED_TIME;

	if (!st->st_esp.present)
	{
		goto failed;
	}

	if (inbound)
	{
		src = &c->spd.that;
		dst = &c->spd.this;
		mark = c->spd.mark_in;
		spi = st->st_esp.our_spi;
	}
	else
	{
		src = &c->spd.this;
		dst = &c->spd.that;
		mark = c->spd.mark_out;
		spi = st->st_esp.attrs.spi;
	}

	host_src = host_create_from_sockaddr((sockaddr_t*)&src->host_addr);
	host_dst = host_create_from_sockaddr((sockaddr_t*)&dst->host_addr);

	switch(hydra->kernel_interface->query_sa(hydra->kernel_interface, host_src,
											 host_dst, spi, IPPROTO_ESP,
											 mark, &bytes_kernel))
	{
		case FAILED:
			goto failed;
		case SUCCESS:
			*bytes = bytes_kernel;
			break;
		case NOT_SUPPORTED:
		default:
			break;
	}

	if (st->st_serialno == c->spd.eroute_owner)
	{
		u_int32_t time_kernel;

		ts_src = traffic_selector_from_subnet(&src->client, src->protocol);
		ts_dst = traffic_selector_from_subnet(&dst->client, dst->protocol);

		if (hydra->kernel_interface->query_policy(hydra->kernel_interface,
							ts_src, ts_dst, inbound ? POLICY_IN : POLICY_OUT,
							mark, &time_kernel) != SUCCESS)
		{
			goto failed;
		}
		*use_time = time_kernel;

		if (inbound &&
			st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
		{
			if (hydra->kernel_interface->query_policy(hydra->kernel_interface,
							ts_src, ts_dst, POLICY_FWD, mark,
							&time_kernel) != SUCCESS)
			{
				goto failed;
			}
			*use_time = max(*use_time, time_kernel);
		}
	}

	result = TRUE;

failed:
	DESTROY_IF(host_src);
	DESTROY_IF(host_dst);
	DESTROY_IF(ts_src);
	DESTROY_IF(ts_dst);
	return result;
}

/**
 * Handler for kernel events (called by thread-pool thread)
 */
kernel_listener_t *kernel_handler;

/**
 * Data for acquire events
 */
typedef struct {
	/** Subnets */
	ip_subnet src, dst;
	/** Transport protocol */
	int proto;
} acquire_data_t;

/**
 * Callback for acquire events (called by main thread)
 */
void handle_acquire(acquire_data_t *this)
{
	record_and_initiate_opportunistic(&this->src, &this->dst, this->proto,
									  "%acquire");
}

METHOD(kernel_listener_t, acquire, bool,
	   kernel_listener_t *this, u_int32_t reqid,
	   traffic_selector_t *src_ts, traffic_selector_t *dst_ts)
{
	if (src_ts && dst_ts)
	{
		acquire_data_t *data;
		DBG(DBG_CONTROL,
			DBG_log("creating acquire event for policy %R === %R "
					"with reqid {%u}", src_ts, dst_ts, reqid));
		INIT(data,
			.src = subnet_from_traffic_selector(src_ts),
			.dst = subnet_from_traffic_selector(dst_ts),
			.proto = src_ts->get_protocol(src_ts),
		);
		pluto->events->queue(pluto->events, (void*)handle_acquire, data, free);
	}
	else
	{
		DBG(DBG_CONTROL,
			DBG_log("ignoring acquire without traffic selectors for policy "
					"with reqid {%u}", reqid));
	}
	DESTROY_IF(src_ts);
	DESTROY_IF(dst_ts);
	return TRUE;
}

/**
 * Data for mapping events
 */
typedef struct {
	/** reqid, spi of affected SA */
	u_int32_t reqid, spi;
	/** new endpont */
	ip_address new_end;
} mapping_data_t;

/**
 * Callback for mapping events (called by main thread)
 */
void handle_mapping(mapping_data_t *this)
{
	process_nat_t_new_mapping(this->reqid, this->spi, &this->new_end);
}


METHOD(kernel_listener_t, mapping, bool,
	   kernel_listener_t *this, u_int32_t reqid, u_int32_t spi, host_t *remote)
{
	mapping_data_t *data;
	DBG(DBG_CONTROL,
		DBG_log("creating mapping event for SA with SPI %.8x and reqid {%u}",
				spi, reqid));
	INIT(data,
		.reqid = reqid,
		.spi = spi,
		.new_end = *(ip_address*)remote->get_sockaddr(remote),
	);
	pluto->events->queue(pluto->events, (void*)handle_mapping, data, free);
	return TRUE;
}

void init_kernel(void)
{
	/* register SA types that we can negotiate */
	can_do_IPcomp = FALSE;  /* until we get a response from the kernel */
	pfkey_register();

	INIT(kernel_handler,
		.acquire = _acquire,
		.mapping = _mapping,
	);
	hydra->kernel_interface->add_listener(hydra->kernel_interface,
										  kernel_handler);
}

void kernel_finalize()
{
	hydra->kernel_interface->remove_listener(hydra->kernel_interface,
											 kernel_handler);
	free(kernel_handler);
}

/* Note: install_inbound_ipsec_sa is only used by the Responder.
 * The Responder will subsequently use install_ipsec_sa for the outbound.
 * The Initiator uses install_ipsec_sa to install both at once.
 */
bool install_inbound_ipsec_sa(struct state *st)
{
	connection_t *const c = st->st_connection;

	/* If our peer has a fixed-address client, check if we already
	 * have a route for that client that conflicts.  We will take this
	 * as proof that that route and the connections using it are
	 * obsolete and should be eliminated.  Interestingly, this is
	 * the only case in which we can tell that a connection is obsolete.
	 */
	passert(c->kind == CK_PERMANENT || c->kind == CK_INSTANCE);
	if (c->spd.that.has_client)
	{
		for (;;)
		{
			struct spd_route *esr;
			connection_t *o = route_owner(c, &esr, NULL, NULL);

			if (o == NULL)
			{
				break;  /* nobody has a route */
			}

			/* note: we ignore the client addresses at this end */
			if (sameaddr(&o->spd.that.host_addr, &c->spd.that.host_addr) &&
				o->interface == c->interface)
			{
				break;  /* existing route is compatible */
			}

			if (o->kind == CK_TEMPLATE && streq(o->name, c->name))
			{
				break;  /* ??? is this good enough?? */
			}

			loglog(RC_LOG_SERIOUS, "route to peer's client conflicts with \"%s\" %s; releasing old connection to free the route"
				, o->name, ip_str(&o->spd.that.host_addr));
			release_connection(o, FALSE);
		}
	}

	DBG(DBG_CONTROL, DBG_log("install_inbound_ipsec_sa() checking if we can route"));
	/* check that we will be able to route and eroute */
	switch (could_route(c))
	{
		case route_easy:
		case route_nearconflict:
			break;
		default:
			return FALSE;
	}

	/* (attempt to) actually set up the SAs */
	return setup_half_ipsec_sa(st, TRUE);
}

/* Install a route and then a prospective shunt eroute or an SA group eroute.
 * Assumption: could_route gave a go-ahead.
 * Any SA Group must have already been created.
 * On failure, steps will be unwound.
 */
bool route_and_eroute(connection_t *c, struct spd_route *sr, struct state *st)
{
	struct spd_route *esr;
	struct spd_route *rosr;
	connection_t *ero      /* who, if anyone, owns our eroute? */
		, *ro = route_owner(c, &rosr, &ero, &esr);
	bool eroute_installed = FALSE
		, firewall_notified = FALSE
		, route_installed = FALSE;

	connection_t *ero_top;

	DBG(DBG_CONTROLMORE,
		DBG_log("route_and_eroute with c: %s (next: %s) ero:%s esr:{%p} ro:%s rosr:{%p} and state: %lu"
				, c->name
				, (c->policy_next ? c->policy_next->name : "none")
				, ero ? ero->name : "null"
				, esr
				, ro ? ro->name : "null"
				, rosr
				, st ? st->st_serialno : 0));

	/* look along the chain of policies for one with the same name */
	ero_top = ero;

#if 0
	/* XXX - mcr this made sense before, and likely will make sense
	 * again, so I'l leaving this to remind me what is up */
	if (ero!= NULL && ero->routing == RT_UNROUTED_KEYED)
		ero = NULL;

	for (ero2 = ero; ero2 != NULL; ero2 = ero->policy_next)
		if ((ero2->kind == CK_TEMPLATE || ero2->kind==CK_SECONDARY)
		&& streq(ero2->name, c->name))
			break;
#endif

	/* install the eroute */

	if (ero != NULL)
	{
		/* We're replacing an eroute */

		/* if no state provided, then install a shunt for later */
		if (st == NULL)
		{
			eroute_installed = shunt_eroute(c, sr, RT_ROUTED_PROSPECTIVE
											, ERO_REPLACE, "replace");
		}
		else
		{
			eroute_installed = sag_eroute(st, sr, ERO_REPLACE, "replace");
		}
#if 0
		/* XXX - MCR. I previously felt that this was a bogus check */
		if (ero != NULL && ero != c && esr != sr)
		{
			/* By elimination, we must be eclipsing ero.  Check. */
			passert(ero->kind == CK_TEMPLATE && streq(ero->name, c->name));
			passert(LHAS(LELEM(RT_ROUTED_PROSPECTIVE) | LELEM(RT_ROUTED_ECLIPSED)
				, esr->routing));
			passert(samesubnet(&esr->this.client, &sr->this.client)
				&& samesubnet(&esr->that.client, &sr->that.client));
		}
#endif
	}
	else
	{
		/* we're adding an eroute */

		/* if no state provided, then install a shunt for later */
		if (st == NULL)
		{
			eroute_installed = shunt_eroute(c, sr, RT_ROUTED_PROSPECTIVE
											, ERO_ADD, "add");
		}
		else
		{
			eroute_installed = sag_eroute(st, sr, ERO_ADD, "add");
		}
	}

	/* notify the firewall of a new tunnel */

	if (eroute_installed)
	{
		/* do we have to notify the firewall?  Yes, if we are installing
		 * a tunnel eroute and the firewall wasn't notified
		 * for a previous tunnel with the same clients.  Any Previous
		 * tunnel would have to be for our connection, so the actual
		 * test is simple.
		 */
		firewall_notified = st == NULL  /* not a tunnel eroute */
			|| sr->eroute_owner != SOS_NOBODY   /* already notified */
			|| do_command(c, sr, st, "up"); /* go ahead and notify */
	}

	/* install the route */

	DBG(DBG_CONTROL,
		DBG_log("route_and_eroute: firewall_notified: %s"
				, firewall_notified ? "true" : "false"));
	if (!firewall_notified)
	{
		/* we're in trouble -- don't do routing */
	}
	else if (ro == NULL)
	{
		/* a new route: no deletion required, but preparation is */
		(void) do_command(c, sr, st, "prepare");    /* just in case; ignore failure */
		route_installed = do_command(c, sr, st, "route");
	}
	else if (routed(sr->routing) || routes_agree(ro, c))
	{
		route_installed = TRUE; /* nothing to be done */
	}
	else
	{
		/* Some other connection must own the route
		 * and the route must disagree.  But since could_route
		 * must have allowed our stealing it, we'll do so.
		 *
		 * A feature of LINUX allows us to install the new route
		 * before deleting the old if the nexthops differ.
		 * This reduces the "window of vulnerability" when packets
		 * might flow in the clear.
		 */
		if (sameaddr(&sr->this.host_nexthop, &esr->this.host_nexthop))
		{
			(void) do_command(ro, sr, st, "unroute");
			route_installed = do_command(c, sr, st, "route");
		}
		else
		{
			route_installed = do_command(c, sr, st, "route");
			(void) do_command(ro, sr, st, "unroute");
		}

		/* record unrouting */
		if (route_installed)
		{
			do {
				passert(!erouted(rosr->routing));
				rosr->routing = RT_UNROUTED;

				/* no need to keep old value */
				ro = route_owner(c, &rosr, NULL, NULL);
			} while (ro != NULL);
		}
	}

	/* all done -- clean up */
	if (route_installed)
	{
		/* Success! */

		if (ero != NULL && ero != c)
		{
			/* check if ero is an ancestor of c. */
			connection_t *ero2;

			for (ero2 = c; ero2 != NULL && ero2 != c; ero2 = ero2->policy_next)
				;

			if (ero2 == NULL)
			{
				/* By elimination, we must be eclipsing ero.  Checked above. */
				if (ero->spd.routing != RT_ROUTED_ECLIPSED)
				{
					ero->spd.routing = RT_ROUTED_ECLIPSED;
					eclipse_count++;
				}
			}
		}

		if (st == NULL)
		{
			passert(sr->eroute_owner == SOS_NOBODY);
			sr->routing = RT_ROUTED_PROSPECTIVE;
		}
		else
		{
			char cib[CONN_INST_BUF];
			sr->routing = RT_ROUTED_TUNNEL;

			DBG(DBG_CONTROL,
				DBG_log("route_and_eroute: instance \"%s\"%s, setting eroute_owner {spd=%p,sr=%p} to #%ld (was #%ld) (newest_ipsec_sa=#%ld)"
						, st->st_connection->name
						, (fmt_conn_instance(st->st_connection, cib), cib)
						, &st->st_connection->spd, sr
						, st->st_serialno
						, sr->eroute_owner
						, st->st_connection->newest_ipsec_sa));
			sr->eroute_owner = st->st_serialno;
		}

		return TRUE;
	}
	else
	{
		/* Failure!  Unwind our work. */
		if (firewall_notified && sr->eroute_owner == SOS_NOBODY)
			(void) do_command(c, sr, st, "down");

		if (eroute_installed)
		{
			/* Restore original eroute, if we can.
			 * Since there is nothing much to be done if the restoration
			 * fails, ignore success or failure.
			 */
			if (ero != NULL)
			{
				/* restore ero's former glory */
				if (esr->eroute_owner == SOS_NOBODY)
				{
					/* note: normal or eclipse case */
					(void) shunt_eroute(ero, esr
										, esr->routing, ERO_REPLACE, "restore");
				}
				else
				{
					/* Try to find state that owned eroute.
					 * Don't do anything if it cannot be found.
					 * This case isn't likely since we don't run
					 * the updown script when replacing a SA group
					 * with its successor (for the same conn).
					 */
					struct state *ost = state_with_serialno(esr->eroute_owner);

					if (ost != NULL)
						(void) sag_eroute(ost, esr, ERO_REPLACE, "restore");
				}
			}
			else
			{
				/* there was no previous eroute: delete whatever we installed */
				if (st == NULL)
				{
					(void) shunt_eroute(c, sr, sr->routing, ERO_DELETE, "delete");
				}
				else
				{
					(void) sag_eroute(st, sr, ERO_DELETE, "delete");
				}
			}
		}

		return FALSE;
	}
}

bool install_ipsec_sa(struct state *st, bool inbound_also)
{
	struct spd_route *sr;

	DBG(DBG_CONTROL, DBG_log("install_ipsec_sa() for #%ld: %s"
							 , st->st_serialno
							 , inbound_also?
							 "inbound and outbound" : "outbound only"));

	switch (could_route(st->st_connection))
	{
		case route_easy:
		case route_nearconflict:
			break;
		default:
			return FALSE;
	}

	/* (attempt to) actually set up the SA group */
	if ((inbound_also && !setup_half_ipsec_sa(st, TRUE)) ||
		!setup_half_ipsec_sa(st, FALSE))
	{
		return FALSE;
	}

	for (sr = &st->st_connection->spd; sr != NULL; sr = sr->next)
	{
		DBG(DBG_CONTROL, DBG_log("sr for #%ld: %s"
								 , st->st_serialno
								 , enum_name(&routing_story, sr->routing)));

		/*
		 * if the eroute owner is not us, then make it us.
		 * See test co-terminal-02, pluto-rekey-01, pluto-unit-02/oppo-twice
		 */
		pexpect(sr->eroute_owner == SOS_NOBODY
				|| sr->routing >= RT_ROUTED_TUNNEL);

		if (sr->eroute_owner != st->st_serialno
			&& sr->routing != RT_UNROUTED_KEYED)
		{
			if (!route_and_eroute(st->st_connection, sr, st))
			{
				delete_ipsec_sa(st, FALSE);
				/* XXX go and unroute any SRs that were successfully
				 * routed already.
				 */
				return FALSE;
			}
		}
	}

	return TRUE;
}

/* delete an IPSEC SA.
 * we may not succeed, but we bull ahead anyway because
 * we cannot do anything better by recognizing failure
 */
void delete_ipsec_sa(struct state *st, bool inbound_only)
{
	if (!inbound_only)
	{
		/* If the state is the eroute owner, we must adjust
		 * the routing for the connection.
		 */
		connection_t *c = st->st_connection;
		struct spd_route *sr;

		passert(st->st_connection);

		for (sr = &c->spd; sr; sr = sr->next)
		{
			if (sr->eroute_owner == st->st_serialno
			&& sr->routing == RT_ROUTED_TUNNEL)
			{
				sr->eroute_owner = SOS_NOBODY;

				/* Routing should become RT_ROUTED_FAILURE,
				 * but if POLICY_FAIL_NONE, then we just go
				 * right back to RT_ROUTED_PROSPECTIVE as if no
				 * failure happened.
				 */
				sr->routing = (c->policy & POLICY_FAIL_MASK) == POLICY_FAIL_NONE
					? RT_ROUTED_PROSPECTIVE : RT_ROUTED_FAILURE;

				(void) do_command(c, sr, st, "down");
				if ((c->policy & POLICY_DONT_REKEY)	&& c->kind == CK_INSTANCE)
				{
					/* in this special case, even if the connection
					 * is still alive (due to an ISAKMP SA),
					 * we get rid of routing.
					 * Even though there is still an eroute, the c->routing
					 * setting will convince unroute_connection to delete it.
					 * unroute_connection would be upset if c->routing == RT_ROUTED_TUNNEL
					 */
					unroute_connection(c);
				}
				else
				{
					(void) shunt_eroute(c, sr, sr->routing, ERO_REPLACE, "replace with shunt");
				}
			}
		}
		(void) teardown_half_ipsec_sa(st, FALSE);
	}
	(void) teardown_half_ipsec_sa(st, TRUE);
}

static bool update_nat_t_ipsec_esp_sa (struct state *st, bool inbound)
{
	connection_t *c = st->st_connection;
	host_t *host_src, *host_dst, *new_src, *new_dst;
	ipsec_spi_t spi = inbound ? st->st_esp.our_spi : st->st_esp.attrs.spi;
	struct end *src = inbound ? &c->spd.that : &c->spd.this,
			   *dst = inbound ? &c->spd.this : &c->spd.that;
	mark_t mark = inbound ? c->spd.mark_in : c->spd.mark_out;
	bool result;

	host_src = host_create_from_sockaddr((sockaddr_t*)&src->host_addr);
	host_dst = host_create_from_sockaddr((sockaddr_t*)&dst->host_addr);

	new_src = host_src->clone(host_src);
	new_dst = host_dst->clone(host_dst);
	new_src->set_port(new_src, src->host_port);
	new_dst->set_port(new_dst, dst->host_port);

	result = hydra->kernel_interface->update_sa(hydra->kernel_interface,
					spi, IPPROTO_ESP, 0 /* cpi */, host_src, host_dst,
					new_src, new_dst, TRUE /* encap */, TRUE /* new_encap */,
					mark) == SUCCESS;

	host_src->destroy(host_src);
	host_dst->destroy(host_dst);
	new_src->destroy(new_src);
	new_dst->destroy(new_dst);

	return result;
}

bool update_ipsec_sa (struct state *st)
{
	if (IS_IPSEC_SA_ESTABLISHED(st->st_state))
	{
		if (st->st_esp.present && (
		   (!update_nat_t_ipsec_esp_sa (st, TRUE)) ||
		   (!update_nat_t_ipsec_esp_sa (st, FALSE))))
		{
			return FALSE;
		}
	}
	else if (IS_ONLY_INBOUND_IPSEC_SA_ESTABLISHED(st->st_state))
	{
		if (st->st_esp.present && !update_nat_t_ipsec_esp_sa (st, FALSE))
		{
			return FALSE;
		}
	}
	else
	{
		DBG_log("assert failed at %s:%d st_state=%d", __FILE__, __LINE__, st->st_state);
		return FALSE;
	}
	return TRUE;
}

/* Check if there was traffic on given SA during the last idle_max
 * seconds. If TRUE, the SA was idle and DPD exchange should be performed.
 * If FALSE, DPD is not necessary. We also return TRUE for errors, as they
 * could mean that the SA is broken and needs to be replace anyway.
 */
bool was_eroute_idle(struct state *st, time_t idle_max, time_t *idle_time)
{
	time_t use_time;
	u_int bytes;
	int ret = TRUE;

	passert(st != NULL);

	if (get_sa_info(st, TRUE, &bytes, &use_time) && use_time != UNDEFINED_TIME)
	{
		*idle_time = time_monotonic(NULL) - use_time;
		ret = *idle_time >= idle_max;
	}

	return ret;
}
