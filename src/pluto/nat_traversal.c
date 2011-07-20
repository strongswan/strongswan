/*
 * Copyright (C) 2010 Tobias Brunner
 * Copyright (C) 2009 Andreas Steffen
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2002-2005 Mathieu Lafon
 * Arkoon Network Security
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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>     /* used only if MSG_NOSIGNAL not defined */
#include <sys/queue.h>

#include <library.h>
#include <crypto/hashers/hasher.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "server.h"
#include "state.h"
#include "connections.h"
#include "packet.h"
#include "demux.h"
#include "kernel.h"
#include "whack.h"
#include "timer.h"
#include "cookie.h"
#include "crypto.h"
#include "vendor.h"
#include "ike_alg.h"
#include "nat_traversal.h"

/* #define FORCE_NAT_TRAVERSAL */
#define NAT_D_DEBUG
#define NAT_T_SUPPORT_LAST_DRAFTS

#ifndef SOL_UDP
#define SOL_UDP 17
#endif

#ifndef UDP_ESPINUDP
#define UDP_ESPINUDP    100
#endif

#define DEFAULT_KEEP_ALIVE_PERIOD  20

#ifdef _IKE_ALG_H
/* Alg patch: hash_digest_len -> hash_digest_size */
#define hash_digest_len hash_digest_size
#endif

bool nat_traversal_enabled = FALSE;
bool nat_traversal_support_non_ike = FALSE;
bool nat_traversal_support_port_floating = FALSE;

static unsigned int _kap = 0;
static unsigned int _ka_evt = 0;
static bool _force_ka = 0;

static const char *natt_version = "0.6c";

void init_nat_traversal (bool activate, unsigned int keep_alive_period,
		bool fka, bool spf)
{
	nat_traversal_enabled = activate;
	nat_traversal_support_non_ike = activate;
#ifdef NAT_T_SUPPORT_LAST_DRAFTS
	nat_traversal_support_port_floating = activate ? spf : FALSE;
#endif
	_force_ka = fka;
	_kap = keep_alive_period ? keep_alive_period : DEFAULT_KEEP_ALIVE_PERIOD;
	plog("  including NAT-Traversal patch (Version %s)%s%s%s"
		 , natt_version, activate ? "" : " [disabled]"
		 , activate & fka ? " [Force KeepAlive]" : ""
		 , activate & !spf ? " [Port Floating disabled]" : "");
}

static void disable_nat_traversal (int type)
{
	if (type == ESPINUDP_WITH_NON_IKE)
		nat_traversal_support_non_ike = FALSE;
	else
		nat_traversal_support_port_floating = FALSE;

	if (!nat_traversal_support_non_ike &&
		!nat_traversal_support_port_floating)
			nat_traversal_enabled = FALSE;
}

static void _natd_hash(const struct hash_desc *oakley_hasher, char *hash,
		u_int8_t *icookie, u_int8_t *rcookie,
		const ip_address *ip, u_int16_t port)
{
	if (is_zero_cookie(icookie))
	{
		DBG_log("_natd_hash: Warning, icookie is zero !!");
	}
	if (is_zero_cookie(rcookie))
	{
		DBG_log("_natd_hash: Warning, rcookie is zero !!");
	}

	/**
	 * draft-ietf-ipsec-nat-t-ike-01.txt
	 *
	 *   HASH = HASH(CKY-I | CKY-R | IP | Port)
	 *
	 * All values in network order
	 */
	{
		chunk_t icookie_chunk = { icookie, COOKIE_SIZE };
		chunk_t rcookie_chunk = { rcookie, COOKIE_SIZE };
		chunk_t port_chunk = chunk_from_thing(port);
		chunk_t addr_chunk;
		hash_algorithm_t hash_alg;
		hasher_t *hasher;
		size_t hash_size;

		hash_alg = oakley_to_hash_algorithm(oakley_hasher->algo_id);
		hasher = lib->crypto->create_hasher(lib->crypto, hash_alg);
		hasher->get_hash(hasher, icookie_chunk, NULL);
		hasher->get_hash(hasher, rcookie_chunk, NULL);
		switch (addrtypeof(ip))
		{
			case AF_INET:
				addr_chunk = chunk_from_thing(ip->u.v4.sin_addr.s_addr);
				break;
			case AF_INET6:
				addr_chunk = chunk_from_thing(ip->u.v6.sin6_addr.s6_addr);
				break;
			default:
				addr_chunk = chunk_empty; /* should never occur */
		}
		hasher->get_hash(hasher, addr_chunk, NULL);
		hasher->get_hash(hasher, port_chunk, hash);
		hash_size = hasher->get_hash_size(hasher);
		hasher->destroy(hasher);
#ifdef NAT_D_DEBUG
		DBG(DBG_NATT,
			DBG_dump_chunk("_natd_hash: icookie=", icookie_chunk);
			DBG_dump_chunk("_natd_hash: rcookie=", rcookie_chunk);
			DBG_dump_chunk("_natd_hash: ip=", addr_chunk);
			DBG_log("_natd_hash: port=%d", port);
			DBG_dump("_natd_hash: hash=", hash, hash_size);
		)
#endif
	}
}

/* Add NAT-Traversal VIDs (supported ones)
 * used when we are Initiator
 */
bool nat_traversal_add_vid(u_int8_t np, pb_stream *outs)
{
	bool r = TRUE;

	if (nat_traversal_support_port_floating)
	{
		u_int8_t last_np = nat_traversal_support_non_ike ?
								ISAKMP_NEXT_VID : np;

		if (r)
			r = out_vendorid(ISAKMP_NEXT_VID, outs, VID_NATT_RFC);
		if (r)
			r = out_vendorid(ISAKMP_NEXT_VID, outs, VID_NATT_IETF_03);
		if (r)
			r = out_vendorid(ISAKMP_NEXT_VID, outs, VID_NATT_IETF_02);
		if (r)
			r = out_vendorid(last_np, outs, VID_NATT_IETF_02_N);
	}
	if (nat_traversal_support_non_ike)
	{
		if (r)
			r = out_vendorid(np, outs, VID_NATT_IETF_00);
	}
	return r;
}

u_int32_t nat_traversal_vid_to_method(unsigned short nat_t_vid)
{
	switch (nat_t_vid)
	{
	case VID_NATT_IETF_00:
		return LELEM(NAT_TRAVERSAL_IETF_00_01);
	case VID_NATT_IETF_02:
	case VID_NATT_IETF_02_N:
	case VID_NATT_IETF_03:
		return LELEM(NAT_TRAVERSAL_IETF_02_03);
	case VID_NATT_RFC:
		return LELEM(NAT_TRAVERSAL_RFC);
	}
	return 0;
}

void nat_traversal_natd_lookup(struct msg_digest *md)
{
	char hash[MAX_DIGEST_LEN];
	struct payload_digest *p;
	struct state *st = md->st;
	int i;

	if (!st || !md->iface || !st->st_oakley.hasher)
	{
		loglog(RC_LOG_SERIOUS, "NAT-Traversal: assert failed %s:%d"
				, __FILE__, __LINE__);
		return;
	}

	/** Count NAT-D **/
	for (p = md->chain[ISAKMP_NEXT_NATD_RFC], i=0; p != NULL; p = p->next, i++);

	/*
	 * We need at least 2 NAT-D (1 for us, many for peer)
	 */
	if (i < 2)
	{
		loglog(RC_LOG_SERIOUS,
			"NAT-Traversal: Only %d NAT-D - Aborting NAT-Traversal negotiation", i);
		st->nat_traversal = 0;
		return;
	}

	/*
	 * First one with my IP & port
	 */
	p = md->chain[ISAKMP_NEXT_NATD_RFC];
	_natd_hash(st->st_oakley.hasher, hash, st->st_icookie, st->st_rcookie,
		&(md->iface->addr), ntohs(st->st_connection->spd.this.host_port));

	if (!(pbs_left(&p->pbs) == st->st_oakley.hasher->hash_digest_len &&
		  memeq(p->pbs.cur, hash, st->st_oakley.hasher->hash_digest_len)))
	{
#ifdef NAT_D_DEBUG
		DBG(DBG_NATT,
			DBG_log("NAT_TRAVERSAL_NAT_BHND_ME");
			DBG_dump("expected NAT-D:", hash
						, st->st_oakley.hasher->hash_digest_len);
			DBG_dump("received NAT-D:", p->pbs.cur, pbs_left(&p->pbs));
		)
#endif
		st->nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_ME);
	}

	/*
	 * The others with sender IP & port
	 */
	_natd_hash(st->st_oakley.hasher, hash, st->st_icookie, st->st_rcookie,
				&(md->sender), ntohs(md->sender_port));
	for (p = p->next, i=0 ; p != NULL; p = p->next)
	{
		if (pbs_left(&p->pbs) == st->st_oakley.hasher->hash_digest_len &&
			memeq(p->pbs.cur, hash, st->st_oakley.hasher->hash_digest_len))
		{
			i++;
		}
	}
	if (!i)
	{
#ifdef NAT_D_DEBUG
		DBG(DBG_NATT,
			DBG_log("NAT_TRAVERSAL_NAT_BHND_PEER");
			DBG_dump("expected NAT-D:", hash
						, st->st_oakley.hasher->hash_digest_len);
			p = md->chain[ISAKMP_NEXT_NATD_RFC];
			for (p = p->next, i=0 ; p != NULL; p = p->next)
			{
				DBG_dump("received NAT-D:", p->pbs.cur, pbs_left(&p->pbs));
			}
		)
#endif
		st->nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_PEER);
	}
#ifdef FORCE_NAT_TRAVERSAL
	st->nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_PEER);
	st->nat_traversal |= LELEM(NAT_TRAVERSAL_NAT_BHND_ME);
#endif
}

bool nat_traversal_add_natd(u_int8_t np, pb_stream *outs,
		struct msg_digest *md)
{
	char hash[MAX_DIGEST_LEN];
	struct state *st = md->st;

	if (!st || !st->st_oakley.hasher)
	{
		loglog(RC_LOG_SERIOUS, "NAT-Traversal: assert failed %s:%d"
						, __FILE__, __LINE__);
		return FALSE;
	}

	DBG(DBG_EMITTING,
		DBG_log("sending NATD payloads")
	)

	/*
	 * First one with sender IP & port
	 */
	_natd_hash(st->st_oakley.hasher, hash, st->st_icookie,
		is_zero_cookie(st->st_rcookie) ? md->hdr.isa_rcookie : st->st_rcookie,
		&(md->sender),
#ifdef FORCE_NAT_TRAVERSAL
		0
#else
		ntohs(md->sender_port)
#endif
	);
	if (!out_generic_raw((st->nat_traversal & NAT_T_WITH_RFC_VALUES
		? ISAKMP_NEXT_NATD_RFC : ISAKMP_NEXT_NATD_DRAFTS), &isakmp_nat_d, outs,
		hash, st->st_oakley.hasher->hash_digest_len, "NAT-D"))
	{
		return FALSE;
	}

	/*
	 * Second one with my IP & port
	 */
	_natd_hash(st->st_oakley.hasher, hash, st->st_icookie,
		is_zero_cookie(st->st_rcookie) ? md->hdr.isa_rcookie : st->st_rcookie,
		&(md->iface->addr),
#ifdef FORCE_NAT_TRAVERSAL
		0
#else
		ntohs(st->st_connection->spd.this.host_port)
#endif
	);
	return (out_generic_raw(np, &isakmp_nat_d, outs,
		hash, st->st_oakley.hasher->hash_digest_len, "NAT-D"));
}

/*
 * nat_traversal_natoa_lookup()
 *
 * Look for NAT-OA in message
 */
void nat_traversal_natoa_lookup(struct msg_digest *md)
{
	struct payload_digest *p;
	struct state *st = md->st;
	int i;
	ip_address ip;

	if (!st || !md->iface)
	{
		loglog(RC_LOG_SERIOUS, "NAT-Traversal: assert failed %s:%d"
				, __FILE__, __LINE__);
		return;
	}

	/* Initialize NAT-OA */
	anyaddr(AF_INET, &st->nat_oa);

	/* Count NAT-OA **/
	for (p = md->chain[ISAKMP_NEXT_NATOA_RFC], i=0; p != NULL; p = p->next, i++);

	DBG(DBG_NATT,
		DBG_log("NAT-Traversal: received %d NAT-OA.", i)
	)

	if (i == 0)
		return;

	if (!(st->nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_PEER)))
	{
		loglog(RC_LOG_SERIOUS, "NAT-Traversal: received %d NAT-OA. "
						"ignored because peer is not NATed", i);
		return;
	}

	if (i > 1)
	{
		loglog(RC_LOG_SERIOUS, "NAT-Traversal: received %d NAT-OA. "
				"using first, ignoring others", i);
	}

	/* Take first */
	p = md->chain[ISAKMP_NEXT_NATOA_RFC];

	DBG(DBG_PARSING,
		DBG_dump("NAT-OA:", p->pbs.start, pbs_room(&p->pbs));
	);

	switch (p->payload.nat_oa.isanoa_idtype)
	{
	case ID_IPV4_ADDR:
		if (pbs_left(&p->pbs) == sizeof(struct in_addr))
		{
			initaddr(p->pbs.cur, pbs_left(&p->pbs), AF_INET, &ip);
		}
		else
		{
			loglog(RC_LOG_SERIOUS, "NAT-Traversal: received IPv4 NAT-OA "
						"with invalid IP size (%d)", (int)pbs_left(&p->pbs));
			return;
		}
		break;
	case ID_IPV6_ADDR:
		if (pbs_left(&p->pbs) == sizeof(struct in6_addr))
		{
			initaddr(p->pbs.cur, pbs_left(&p->pbs), AF_INET6, &ip);
		}
		else
		{
			loglog(RC_LOG_SERIOUS, "NAT-Traversal: received IPv6 NAT-OA "
						"with invalid IP size (%d)", (int)pbs_left(&p->pbs));
			return;
		}
		break;
	default:
		loglog(RC_LOG_SERIOUS, "NAT-Traversal: "
						"invalid ID Type (%d) in NAT-OA - ignored",
						p->payload.nat_oa.isanoa_idtype);
			return;
	}

	DBG(DBG_NATT,
		{
			char ip_t[ADDRTOT_BUF];
			addrtot(&ip, 0, ip_t, sizeof(ip_t));

			DBG_log("received NAT-OA: %s", ip_t);
		}
	)

	if (isanyaddr(&ip))
		loglog(RC_LOG_SERIOUS, "NAT-Traversal: received %%any NAT-OA...");
	else
		st->nat_oa = ip;
}

bool nat_traversal_add_natoa(u_int8_t np, pb_stream *outs,
		struct state *st)
{
	struct isakmp_nat_oa natoa;
	pb_stream pbs;
	unsigned char ip_val[sizeof(struct in6_addr)];
	size_t ip_len = 0;
	ip_address *ip;

	if ((!st) || (!st->st_connection))
	{
		loglog(RC_LOG_SERIOUS, "NAT-Traversal: assert failed %s:%d"
						, __FILE__, __LINE__);
		return FALSE;
	}
	ip = &(st->st_connection->spd.this.host_addr);

	memset(&natoa, 0, sizeof(natoa));
	natoa.isanoa_np = np;

	switch (addrtypeof(ip))
	{
	case AF_INET:
		ip_len = sizeof(ip->u.v4.sin_addr.s_addr);
		memcpy(ip_val, &ip->u.v4.sin_addr.s_addr, ip_len);
		natoa.isanoa_idtype = ID_IPV4_ADDR;
		break;
	case AF_INET6:
		ip_len = sizeof(ip->u.v6.sin6_addr.s6_addr);
		memcpy(ip_val, &ip->u.v6.sin6_addr.s6_addr, ip_len);
		natoa.isanoa_idtype = ID_IPV6_ADDR;
		break;
	default:
		loglog(RC_LOG_SERIOUS, "NAT-Traversal: "
						"invalid addrtypeof()=%d", addrtypeof(ip));
		return FALSE;
	}

	if (!out_struct(&natoa, &isakmp_nat_oa, outs, &pbs))
		return FALSE;

	if (!out_raw(ip_val, ip_len, &pbs, "NAT-OA"))
		return FALSE;

	DBG(DBG_NATT,
		DBG_dump("NAT-OA (S):", ip_val, ip_len)
	)

	close_output_pbs(&pbs);
	return TRUE;
}

void nat_traversal_show_result (u_int32_t nt, u_int16_t sport)
{
	const char *mth = NULL, *rslt = NULL;

	switch (nt & NAT_TRAVERSAL_METHOD)
	{
	case LELEM(NAT_TRAVERSAL_IETF_00_01):
		mth = natt_type_bitnames[0];
		break;
	case LELEM(NAT_TRAVERSAL_IETF_02_03):
		mth = natt_type_bitnames[1];
		break;
	case LELEM(NAT_TRAVERSAL_RFC):
		mth = natt_type_bitnames[2];
		break;
	}

	switch (nt & NAT_T_DETECTED)
	{
	case 0:
		rslt = "no NAT detected";
		break;
	case LELEM(NAT_TRAVERSAL_NAT_BHND_ME):
		rslt = "i am NATed";
		break;
	case LELEM(NAT_TRAVERSAL_NAT_BHND_PEER):
		rslt = "peer is NATed";
		break;
	case LELEM(NAT_TRAVERSAL_NAT_BHND_ME) | LELEM(NAT_TRAVERSAL_NAT_BHND_PEER):
		rslt = "both are NATed";
		break;
	}

	loglog(RC_LOG_SERIOUS,
		"NAT-Traversal: Result using %s: %s",
		mth ? mth : "unknown method",
		rslt ? rslt : "unknown result"
	);

	if ((nt & LELEM(NAT_TRAVERSAL_NAT_BHND_PEER))
	&&  (sport == IKE_UDP_PORT)
	&&  ((nt & NAT_T_WITH_PORT_FLOATING)==0))
	{
		loglog(RC_LOG_SERIOUS,
				"Warning: peer is NATed but source port is still udp/%d. "
				"Ipsec-passthrough NAT device suspected -- NAT-T may not work.",
				IKE_UDP_PORT
		);
	}
}

int nat_traversal_espinudp_socket (int sk, u_int32_t type)
{
	int r = setsockopt(sk, SOL_UDP, UDP_ESPINUDP, &type, sizeof(type));

	if (r < 0 && errno == ENOPROTOOPT)
	{
		loglog(RC_LOG_SERIOUS,
				"NAT-Traversal: ESPINUDP(%d) not supported by kernel -- "
				"NAT-T disabled", type);
		disable_nat_traversal(type);
	}
	return r;
}

void nat_traversal_new_ka_event (void)
{
	if (_ka_evt)
		return;  /* event already scheduled */

	event_schedule(EVENT_NAT_T_KEEPALIVE, _kap, NULL);
	_ka_evt = 1;
}

static void nat_traversal_send_ka (struct state *st)
{
	static unsigned char ka_payload = 0xff;
	chunk_t sav;

	DBG(DBG_NATT,
		DBG_log("ka_event: send NAT-KA to %s:%d",
				ip_str(&st->st_connection->spd.that.host_addr),
				st->st_connection->spd.that.host_port);
	)

	/* save state chunk */
	sav = st->st_tpacket;

	/* send keep alive */
	st->st_tpacket = chunk_create(&ka_payload, 1);
	send_packet(st, "NAT-T Keep Alive");

	/* restore state chunk */
	st->st_tpacket = sav;
}

/**
 * Find ISAKMP States with NAT-T and send keep-alive
 */
static void nat_traversal_ka_event_state (struct state *st, void *data)
{
	unsigned int *_kap_st = (unsigned int *)data;
	const connection_t *c = st->st_connection;

	if (!c)
		return;

	if ((st->st_state == STATE_MAIN_R3 || st->st_state == STATE_MAIN_I4)
	&&  (st->nat_traversal & NAT_T_DETECTED)
	&&  ((st->nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_ME)) || _force_ka))
	{
		/*
		 * - ISAKMP established
		 * - NAT-Traversal detected
		 * - NAT-KeepAlive needed (we are NATed)
		 */
		if (c->newest_isakmp_sa != st->st_serialno)
		{
			/*
			 * if newest is also valid, ignore this one, we will only use
			 * newest.
			 */
			struct state *st_newest;

			st_newest = state_with_serialno(c->newest_isakmp_sa);
			if (st_newest
			&& (st_newest->st_state == STATE_MAIN_R3 || st_newest->st_state == STATE_MAIN_I4)
			&& (st_newest->nat_traversal & NAT_T_DETECTED)
			&& ((st_newest->nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_ME)) || _force_ka))
			{
				return;
			}
		}
		set_cur_state(st);
		nat_traversal_send_ka(st);
		reset_cur_state();
		(*_kap_st)++;
	}
}

void nat_traversal_ka_event (void)
{
	unsigned int _kap_st = 0;

	_ka_evt = 0;  /* ready to be reschedule */

	for_each_state((void *)nat_traversal_ka_event_state, &_kap_st);

	/* if there are still states who needs Keep-Alive, schedule new event */
	if (_kap_st)
		nat_traversal_new_ka_event();
}

struct _new_mapp_nfo {
		ip_address addr;
		u_int16_t sport, dport;
};

static void nat_traversal_find_new_mapp_state (struct state *st, void *data)
{
	connection_t *c = st->st_connection;
	struct _new_mapp_nfo *nfo = (struct _new_mapp_nfo *)data;

	if (c != NULL
	&& sameaddr(&c->spd.that.host_addr, &(nfo->addr))
	&&  c->spd.that.host_port == nfo->sport)
	{

		/* change host port */
		c->spd.that.host_port = nfo->dport;

		if (IS_IPSEC_SA_ESTABLISHED(st->st_state)
		||  IS_ONLY_INBOUND_IPSEC_SA_ESTABLISHED(st->st_state))
		{
			if (!update_ipsec_sa(st))
			{
				/*
				 * If ipsec update failed, restore old port or we'll
				 * not be able to update anymore.
				 */
				c->spd.that.host_port = nfo->sport;
			}
		}
	}
}

static int nat_traversal_new_mapping(const ip_address *src, u_int16_t sport,
		const ip_address *dst, u_int16_t dport)
{
	char srca[ADDRTOT_BUF], dsta[ADDRTOT_BUF];
	struct _new_mapp_nfo nfo;

	addrtot(src, 0, srca, ADDRTOT_BUF);
	addrtot(dst, 0, dsta, ADDRTOT_BUF);

	if (!sameaddr(src, dst))
	{
		loglog(RC_LOG_SERIOUS, "nat_traversal_new_mapping: "
				"address change currently not supported [%s:%d,%s:%d]",
				srca, sport, dsta, dport);
		return -1;
	}

	if (sport == dport)
	{
		/* no change */
		return 0;
	}

	DBG_log("NAT-T: new mapping %s:%d/%d)", srca, sport, dport);

	nfo.addr = *src;
	nfo.sport = sport;
	nfo.dport = dport;

	for_each_state((void *)nat_traversal_find_new_mapp_state, &nfo);

	return 0;
}

void nat_traversal_change_port_lookup(struct msg_digest *md, struct state *st)
{
	connection_t *c = st ? st->st_connection : NULL;
	struct iface *i = NULL;

	if ((st == NULL) || (c == NULL))
		return;

	if (md)
	{
		/*
		 * If source port has changed, update (including other states and
		 * established kernel SA)
		 */
		if (c->spd.that.host_port != md->sender_port)
		{
			nat_traversal_new_mapping(&c->spd.that.host_addr, c->spd.that.host_port,
						&c->spd.that.host_addr, md->sender_port);
		}

		/*
		 * If interface type has changed, update local port (500/4500)
		 */
		if ((c->spd.this.host_port == NAT_T_IKE_FLOAT_PORT && !md->iface->ike_float)
		||  (c->spd.this.host_port != NAT_T_IKE_FLOAT_PORT &&  md->iface->ike_float))
		{
			c->spd.this.host_port = (md->iface->ike_float)
				? NAT_T_IKE_FLOAT_PORT : pluto_port;

			DBG(DBG_NATT,
				DBG_log("NAT-T: updating local port to %d", c->spd.this.host_port);
			);
		}
	}

	/*
	 * If we're initiator and NAT-T (with port floating) is detected, we
	 * need to change port (MAIN_I3 or QUICK_I1)
	 */
	if ((st->st_state == STATE_MAIN_I3 || st->st_state == STATE_QUICK_I1)
	&&  (st->nat_traversal & NAT_T_WITH_PORT_FLOATING)
	&&  (st->nat_traversal & NAT_T_DETECTED)
	&&  (c->spd.this.host_port != NAT_T_IKE_FLOAT_PORT))
	{
		DBG(DBG_NATT,
			DBG_log("NAT-T: floating to port %d", NAT_T_IKE_FLOAT_PORT);
		)
		c->spd.this.host_port = NAT_T_IKE_FLOAT_PORT;
		c->spd.that.host_port = NAT_T_IKE_FLOAT_PORT;
		/*
		 * Also update pending connections or they will be deleted if uniqueids
		 * option is set.
		 */
		update_pending(st, st);
	}

	/*
	 * Find valid interface according to local port (500/4500)
	 */
	if ((c->spd.this.host_port == NAT_T_IKE_FLOAT_PORT && !c->interface->ike_float)
	||  (c->spd.this.host_port != NAT_T_IKE_FLOAT_PORT &&  c->interface->ike_float))
	{
		for (i = interfaces; i !=  NULL; i = i->next)
		{
			if (sameaddr(&c->interface->addr, &i->addr)
			&& i->ike_float != c->interface->ike_float)
			{
				DBG(DBG_NATT,
					DBG_log("NAT-T: using interface %s:%d", i->rname,
						i->ike_float ? NAT_T_IKE_FLOAT_PORT : pluto_port);
				)
				c->interface = i;
				break;
			}
		}
	}
}

struct _new_kernel_mapp_nfo {
		u_int32_t reqid;
		u_int32_t spi;
		ip_address *addr;
};

static void nat_t_new_kernel_mapp (struct state *st, void *data)
{
	connection_t *c = st->st_connection;
	struct _new_kernel_mapp_nfo *nfo = (struct _new_kernel_mapp_nfo *)data;

	if (c != NULL && st->st_esp.present
		&&  nfo->spi == st->st_esp.our_spi
		&&  nfo->reqid == c->spd.reqid)
	{
		u_int16_t port = ntohs(portof(nfo->addr));

		DBG(DBG_NATT, {
			char text_said[SATOT_BUF];
			char olda[ADDRTOT_BUF];
			char newa[ADDRTOT_BUF];
			ip_said said;

			initsaid(&c->spd.that.host_addr, nfo->spi, SA_ESP, &said);
			satot(&said, 0, text_said, SATOT_BUF);
			addrtot(&c->spd.that.host_addr, 0, olda, ADDRTOT_BUF);
			addrtot(nfo->addr, 0, newa, ADDRTOT_BUF);

			DBG_log("new kernel mapping %s %s:%d %s:%d",
					text_said, olda, c->spd.that.host_port, newa, port);
		})

		nat_traversal_new_mapping(&c->spd.that.host_addr, c->spd.that.host_port,
								  nfo->addr, port);
	}
}

void process_nat_t_new_mapping(u_int32_t reqid, u_int32_t spi,
							   ip_address *new_end)
{
	struct _new_kernel_mapp_nfo nfo = {
		.reqid = reqid,
		.spi = spi,
		.addr = new_end,
	};
	for_each_state((void *)nat_t_new_kernel_mapp, &nfo);
}

