/* routines for state objects
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2009 Andreas Steffen - Hochschule fuer Technik Rapperswil
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
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/queue.h>

#include <freeswan.h>

#include <library.h>
#include <crypto/rngs/rng.h>

#include "constants.h"
#include "defs.h"
#include "connections.h"
#include "state.h"
#include "kernel.h"
#include "log.h"
#include "packet.h"     /* so we can calculate sizeof(struct isakmp_hdr) */
#include "keys.h"       /* for free_public_key */
#include "timer.h"
#include "whack.h"
#include "demux.h"      /* needs packet.h */
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "crypto.h"

/*
 * Global variables: had to go somewhere, might as well be this file.
 */

u_int16_t pluto_port = IKE_UDP_PORT;    /* Pluto's port */

/*
 * This file has the functions that handle the
 * state hash table and the Message ID list.
 */

/* Message-IDs
 *
 * A Message ID is contained in each IKE message header.
 * For Phase 1 exchanges (Main and Aggressive), it will be zero.
 * For other exchanges, which must be under the protection of an
 * ISAKMP SA, the Message ID must be unique within that ISAKMP SA.
 * Effectively, this labels the message as belonging to a particular
 * exchange.
 * BTW, we feel this uniqueness allows rekeying to be somewhat simpler
 * than specified by draft-jenkins-ipsec-rekeying-06.txt.
 *
 * A MessageID is a 32 bit unsigned number.  We represent the value
 * internally in network order -- they are just blobs to us.
 * They are unsigned numbers to make hashing and comparing easy.
 *
 * The following mechanism is used to allocate message IDs.  This
 * requires that we keep track of which numbers have already been used
 * so that we don't allocate one in use.
 */

struct msgid_list
{
	msgid_t               msgid; /* network order */
	struct msgid_list     *next;
};

bool reserve_msgid(struct state *isakmp_sa, msgid_t msgid)
{
	struct msgid_list *p;

	passert(msgid != MAINMODE_MSGID);
	passert(IS_ISAKMP_ENCRYPTED(isakmp_sa->st_state));

	for (p = isakmp_sa->st_used_msgids; p != NULL; p = p->next)
		if (p->msgid == msgid)
			return FALSE;

	p = malloc_thing(struct msgid_list);
	p->msgid = msgid;
	p->next = isakmp_sa->st_used_msgids;
	isakmp_sa->st_used_msgids = p;
	return TRUE;
}

msgid_t generate_msgid(struct state *isakmp_sa)
{
	int timeout = 100;  /* only try so hard for unique msgid */
	msgid_t msgid;
	rng_t *rng;

	passert(IS_ISAKMP_ENCRYPTED(isakmp_sa->st_state));
	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);

	for (;;)
	{
		rng->get_bytes(rng, sizeof(msgid), (void *) &msgid);
		if (msgid != 0 && reserve_msgid(isakmp_sa, msgid))
		{
			break;
		}
		if (--timeout == 0)
		{
			plog("gave up looking for unique msgid; using 0x%08lx"
				, (unsigned long) msgid);
			break;
		}
	}
	rng->destroy(rng);
	return msgid;
}


/* state table functions */

#define STATE_TABLE_SIZE 32

static struct state *statetable[STATE_TABLE_SIZE];

static struct state **state_hash(const u_char *icookie, const u_char *rcookie,
								 const ip_address *peer)
{
	u_int i = 0, j;
	const unsigned char *byte_ptr;
	size_t length = addrbytesptr(peer, &byte_ptr);

	DBG(DBG_RAW | DBG_CONTROL,
		DBG_dump("ICOOKIE:", icookie, COOKIE_SIZE);
		DBG_dump("RCOOKIE:", rcookie, COOKIE_SIZE);
		DBG_dump("peer:", byte_ptr, length));

	/* XXX the following hash is pretty pathetic */

	for (j = 0; j < COOKIE_SIZE; j++)
		i = i * 407 + icookie[j] + rcookie[j];

	for (j = 0; j < length; j++)
		i = i * 613 + byte_ptr[j];

	i = i % STATE_TABLE_SIZE;

	DBG(DBG_CONTROL, DBG_log("state hash entry %d", i));

	return &statetable[i];
}

/* Get a state object.
 * Caller must schedule an event for this object so that it doesn't leak.
 * Caller must insert_state().
 */
struct state *new_state(void)
{
	/* initialized all to zero & NULL */
	static const struct state blank_state = {
		.st_serialno = 0,
	};
	static so_serial_t next_so = SOS_FIRST;
	struct state *st;

	st = clone_thing(blank_state);
	st->st_serialno = next_so++;
	passert(next_so > SOS_FIRST);       /* overflow can't happen! */
	st->st_whack_sock = NULL_FD;
	DBG(DBG_CONTROL, DBG_log("creating state object #%lu at %p",
		st->st_serialno, (void *) st));
	return st;
}

/*
 * Initialize the state table (and mask*).
 */
void init_states(void)
{
	int i;

	for (i = 0; i < STATE_TABLE_SIZE; i++)
		statetable[i] = (struct state *) NULL;
}

/* Find the state object with this serial number.
 * This allows state object references that don't turn into dangerous
 * dangling pointers: reference a state by its serial number.
 * Returns NULL if there is no such state.
 * If this turns out to be a significant CPU hog, it could be
 * improved to use a hash table rather than sequential seartch.
 */
struct state *state_with_serialno(so_serial_t sn)
{
	if (sn >= SOS_FIRST)
	{
		struct state *st;
		int i;

		for (i = 0; i < STATE_TABLE_SIZE; i++)
			for (st = statetable[i]; st != NULL; st = st->st_hashchain_next)
				if (st->st_serialno == sn)
					return st;
	}
	return NULL;
}

/* Insert a state object in the hash table. The object is inserted
 * at the beginning of list.
 * Needs cookies, connection, and msgid.
 */
void insert_state(struct state *st)
{
	struct state **p = state_hash(st->st_icookie, st->st_rcookie
		, &st->st_connection->spd.that.host_addr);

	passert(st->st_hashchain_prev == NULL && st->st_hashchain_next == NULL);

	if (*p != NULL)
	{
		passert((*p)->st_hashchain_prev == NULL);
		(*p)->st_hashchain_prev = st;
	}
	st->st_hashchain_next = *p;
	*p = st;

	/* Ensure that somebody is in charge of killing this state:
	 * if no event is scheduled for it, schedule one to discard the state.
	 * If nothing goes wrong, this event will be replaced by
	 * a more appropriate one.
	 */
	if (st->st_event == NULL)
		event_schedule(EVENT_SO_DISCARD, 0, st);
}

/* unlink a state object from the hash table, but don't free it
 */
void unhash_state(struct state *st)
{
	/* unlink from forward chain */
	struct state **p = st->st_hashchain_prev == NULL
		? state_hash(st->st_icookie, st->st_rcookie
					 , &st->st_connection->spd.that.host_addr)
		: &st->st_hashchain_prev->st_hashchain_next;

	/* unlink from forward chain */
	passert(*p == st);
	*p = st->st_hashchain_next;

	/* unlink from backward chain */
	if (st->st_hashchain_next != NULL)
	{
		passert(st->st_hashchain_next->st_hashchain_prev == st);
		st->st_hashchain_next->st_hashchain_prev = st->st_hashchain_prev;
	}

	st->st_hashchain_next = st->st_hashchain_prev = NULL;
}

/* Free the Whack socket file descriptor.
 * This has the side effect of telling Whack that we're done.
 */
void release_whack(struct state *st)
{
	close_any(st->st_whack_sock);
}

/**
 * Delete a state object
 */
void delete_state(struct state *st)
{
	connection_t *const c = st->st_connection;
	struct state *old_cur_state = cur_state == st? NULL : cur_state;

	set_cur_state(st);

	/* If DPD is enabled on this state object, clear any pending events */
	if(st->st_dpd_event != NULL)
			delete_dpd_event(st);

	/* if there is a suspended state transition, disconnect us */
	if (st->st_suspended_md != NULL)
	{
		passert(st->st_suspended_md->st == st);
		st->st_suspended_md->st = NULL;
	}

	/* tell the other side of any IPSEC SAs that are going down */
	if (IS_IPSEC_SA_ESTABLISHED(st->st_state)
	|| IS_ISAKMP_SA_ESTABLISHED(st->st_state))
		send_delete(st);

	delete_event(st);   /* delete any pending timer event */

	/* Ditch anything pending on ISAKMP SA being established.
	 * Note: this must be done before the unhash_state to prevent
	 * flush_pending_by_state inadvertently and prematurely
	 * deleting our connection.
	 */
	flush_pending_by_state(st);

	/* effectively, this deletes any ISAKMP SA that this state represents */
	unhash_state(st);

	/* tell kernel to delete any IPSEC SA
	 * ??? we ought to tell peer to delete IPSEC SAs
	 */
	if (IS_IPSEC_SA_ESTABLISHED(st->st_state))
		delete_ipsec_sa(st, FALSE);
	else if (IS_ONLY_INBOUND_IPSEC_SA_ESTABLISHED(st->st_state))
		delete_ipsec_sa(st, TRUE);

	if (c->newest_ipsec_sa == st->st_serialno)
		c->newest_ipsec_sa = SOS_NOBODY;

	if (c->newest_isakmp_sa == st->st_serialno)
		c->newest_isakmp_sa = SOS_NOBODY;

	st->st_connection = NULL;   /* we might be about to free it */
	cur_state = old_cur_state;  /* without st_connection, st isn't complete */
	connection_discard(c);

	release_whack(st);

	/* from here on we are just freeing RAM */

	{
		struct msgid_list *p = st->st_used_msgids;

		while (p != NULL)
		{
			struct msgid_list *q = p;
			p = p->next;
			free(q);
		}
	}

	unreference_key(&st->st_peer_pubkey);

	DESTROY_IF(st->st_dh);

	chunk_clear(&st->st_tpacket);
	chunk_clear(&st->st_rpacket);
	chunk_clear(&st->st_p1isa);
	chunk_clear(&st->st_gi);
	chunk_clear(&st->st_gr);
	chunk_clear(&st->st_shared);
	chunk_clear(&st->st_ni);
	chunk_clear(&st->st_nr);
	chunk_clear(&st->st_skeyid);
	chunk_clear(&st->st_skeyid_d);
	chunk_clear(&st->st_skeyid_a);
	chunk_clear(&st->st_skeyid_e);
	chunk_clear(&st->st_enc_key);

	free(st->st_ah.our_keymat);
	free(st->st_ah.peer_keymat);
	free(st->st_esp.our_keymat);
	free(st->st_esp.peer_keymat);

	free(st);
}

/**
 * Is a connection in use by some state?
 */
bool states_use_connection(connection_t *c)
{
	/* are there any states still using it? */
	struct state *st = NULL;
	int i;

	for (i = 0; st == NULL && i < STATE_TABLE_SIZE; i++)
		for (st = statetable[i]; st != NULL; st = st->st_hashchain_next)
			if (st->st_connection == c)
				return TRUE;

	return FALSE;
}

/**
 * Delete all states that were created for a given connection.
 * if relations == TRUE, then also delete states that share
 * the same phase 1 SA.
 */
void delete_states_by_connection(connection_t *c, bool relations)
{
	int pass;
	/* this kludge avoids an n^2 algorithm */
	enum connection_kind ck = c->kind;
	struct spd_route *sr;

	/* save this connection's isakmp SA, since it will get set to later SOS_NOBODY */
	so_serial_t parent_sa = c->newest_isakmp_sa;

	if (ck == CK_INSTANCE)
		c->kind = CK_GOING_AWAY;

	/* We take two passes so that we delete any ISAKMP SAs last.
	 * This allows Delete Notifications to be sent.
	 * ?? We could probably double the performance by caching any
	 * ISAKMP SA states found in the first pass, avoiding a second.
	 */
	for (pass = 0; pass != 2; pass++)
	{
		int i;

		/* For each hash chain... */
		for (i = 0; i < STATE_TABLE_SIZE; i++)
		{
			struct state *st;

			/* For each state in the hash chain... */
			for (st = statetable[i]; st != NULL; )
			{
				struct state *this = st;

				st = st->st_hashchain_next;     /* before this is deleted */


				if ((this->st_connection == c
						|| (relations && parent_sa != SOS_NOBODY
						&& this->st_clonedfrom == parent_sa))
						&& (pass == 1 || !IS_ISAKMP_SA_ESTABLISHED(this->st_state)))
				{
					struct state *old_cur_state
						= cur_state == this? NULL : cur_state;
#ifdef DEBUG
					lset_t old_cur_debugging = cur_debugging;
#endif

					set_cur_state(this);
					plog("deleting state (%s)"
						, enum_show(&state_names, this->st_state));
					delete_state(this);
					cur_state = old_cur_state;
#ifdef DEBUG
					cur_debugging = old_cur_debugging;
#endif
				}
			}
		}
	}

	sr = &c->spd;
	while (sr != NULL)
	{
		passert(sr->eroute_owner == SOS_NOBODY);
		passert(sr->routing != RT_ROUTED_TUNNEL);
		sr = sr->next;
	}
	c->kind = ck;
}

/**
 * Walk through the state table, and delete each state whose phase 1 (IKE)
 * peer is among those given.
 */
void delete_states_by_peer(ip_address *peer)
{
	char peerstr[ADDRTOT_BUF];
	int i;

	addrtot(peer, 0, peerstr, sizeof(peerstr));

	/* For each hash chain... */
	for (i = 0; i < STATE_TABLE_SIZE; i++)
	{
		struct state *st;

		/* For each state in the hash chain... */
		for (st = statetable[i]; st != NULL; )
		{
			struct state *this = st;
			struct spd_route *sr;
			connection_t *c = this->st_connection;

			st = st->st_hashchain_next; /* before this is deleted */

			/* ??? Is it not the case that the peer is the same for all spds? */
			for (sr = &c->spd; sr != NULL; sr = sr->next)
			{
				if (sameaddr(&sr->that.host_addr, peer))
				{
					plog("peer %s for connection %s deleting - claimed to have crashed"
						 , peerstr
						 , c->name);
					delete_states_by_connection(c, TRUE);
					if (c->kind == CK_INSTANCE)
						delete_connection(c, TRUE);
					break;      /* can only delete it once */
				}
			}
		}
	}
}

/* Duplicate a Phase 1 state object, to create a Phase 2 object.
 * Caller must schedule an event for this object so that it doesn't leak.
 * Caller must insert_state().
 */
struct state *duplicate_state(struct state *st)
{
	struct state *nst;

	DBG(DBG_CONTROL, DBG_log("duplicating state object #%lu",
		st->st_serialno));

	/* record use of the Phase 1 state */
	st->st_outbound_count++;
	st->st_outbound_time = now();

	nst = new_state();

	memcpy(nst->st_icookie, st->st_icookie, COOKIE_SIZE);
	memcpy(nst->st_rcookie, st->st_rcookie, COOKIE_SIZE);

	nst->st_connection = st->st_connection;
	nst->st_doi = st->st_doi;
	nst->st_situation = st->st_situation;
	nst->st_clonedfrom = st->st_serialno;
	nst->st_oakley = st->st_oakley;
	nst->st_modecfg = st->st_modecfg;
	nst->st_skeyid_d = chunk_clone(st->st_skeyid_d);
	nst->st_skeyid_a = chunk_clone(st->st_skeyid_a);
	nst->st_skeyid_e = chunk_clone(st->st_skeyid_e);
	nst->st_enc_key = chunk_clone(st->st_enc_key);

	return nst;
}

#if 1
void for_each_state(void *(f)(struct state *, void *data), void *data)
{
		struct state *st, *ocs = cur_state;
		int i;
		for (i=0; i<STATE_TABLE_SIZE; i++) {
				for (st = statetable[i]; st != NULL; st = st->st_hashchain_next) {
						set_cur_state(st);
						f(st, data);
				}
		}
		cur_state = ocs;
}
#endif

/**
 * Find a state object.
 */
struct state *find_state(const u_char *icookie, const u_char *rcookie,
						 const ip_address *peer, msgid_t msgid)
{
	struct state *st = *state_hash(icookie, rcookie, peer);

	while (st != (struct state *) NULL)
	{
		if (sameaddr(peer, &st->st_connection->spd.that.host_addr)
		&& memeq(icookie, st->st_icookie, COOKIE_SIZE)
		&& memeq(rcookie, st->st_rcookie, COOKIE_SIZE)
		&& msgid == st->st_msgid)
		{
			break;
		}
		else
		{
			st = st->st_hashchain_next;
		}
	}
	DBG(DBG_CONTROL,
		if (st == NULL)
			DBG_log("state object not found");
		else
			DBG_log("state object #%lu found, in %s"
				, st->st_serialno
				, enum_show(&state_names, st->st_state)));

	return st;
}

/**
 * Find the state that sent a packet
 * ??? this could be expensive -- it should be rate-limited to avoid DoS
 */
struct state *find_sender(size_t packet_len, u_char *packet)
{
	int i;
	struct state *st;

	if (packet_len >= sizeof(struct isakmp_hdr))
	{
		for (i = 0; i < STATE_TABLE_SIZE; i++)
		{
			for (st = statetable[i]; st != NULL; st = st->st_hashchain_next)
			{
				if (st->st_tpacket.ptr != NULL
				&& st->st_tpacket.len == packet_len
				&& memeq(st->st_tpacket.ptr, packet, packet_len))
				{
					return st;
				}
			}
		}
	}
	return NULL;
}

struct state *find_phase2_state_to_delete(const struct state *p1st,
										  u_int8_t protoid, ipsec_spi_t spi,
										  bool *bogus)
{
	struct state *st;
	int i;

	*bogus = FALSE;
	for (i = 0; i < STATE_TABLE_SIZE; i++)
	{
		for (st = statetable[i]; st != NULL; st = st->st_hashchain_next)
		{
			if (IS_IPSEC_SA_ESTABLISHED(st->st_state)
			&& p1st->st_connection->host_pair == st->st_connection->host_pair
			&& same_peer_ids(p1st->st_connection, st->st_connection, NULL))
			{
				struct ipsec_proto_info *pr = protoid == PROTO_IPSEC_AH
					? &st->st_ah : &st->st_esp;

				if (pr->present)
				{
					if (pr->attrs.spi == spi)
						return st;
					if (pr->our_spi == spi)
						*bogus = TRUE;
				}
			}
		}
	}
	return NULL;
}

/**
 * Find newest Phase 1 negotiation state object for suitable for connection c
 */
struct state *find_phase1_state(const connection_t *c, lset_t ok_states)
{
	struct state
		*st,
		*best = NULL;
	int i;

	for (i = 0; i < STATE_TABLE_SIZE; i++)
		for (st = statetable[i]; st != NULL; st = st->st_hashchain_next)
			if (LHAS(ok_states, st->st_state)
			&& c->host_pair == st->st_connection->host_pair
			&& same_peer_ids(c, st->st_connection, NULL)
			&& (best == NULL || best->st_serialno < st->st_serialno))
				best = st;

	return best;
}

void state_eroute_usage(ip_subnet *ours, ip_subnet *his, unsigned long count,
						time_t nw)
{
	struct state *st;
	int i;

	for (i = 0; i < STATE_TABLE_SIZE; i++)
	{
		for (st = statetable[i]; st != NULL; st = st->st_hashchain_next)
		{
			connection_t *c = st->st_connection;

			/* XXX spd-enum */
			if (IS_IPSEC_SA_ESTABLISHED(st->st_state)
				&& c->spd.eroute_owner == st->st_serialno
				&& c->spd.routing == RT_ROUTED_TUNNEL
				&& samesubnet(&c->spd.this.client, ours)
				&& samesubnet(&c->spd.that.client, his))
			{
				if (st->st_outbound_count != count)
				{
					st->st_outbound_count = count;
					st->st_outbound_time = nw;
				}
				return;
			}
		}
	}
	DBG(DBG_CONTROL,
		{
			char ourst[SUBNETTOT_BUF];
			char hist[SUBNETTOT_BUF];

			subnettot(ours, 0, ourst, sizeof(ourst));
			subnettot(his, 0, hist, sizeof(hist));
			DBG_log("unknown tunnel eroute %s -> %s found in scan"
				, ourst, hist);
		});
}

void fmt_state(bool all, struct state *st, time_t n, char *state_buf,
			   size_t state_buf_len, char *state_buf2, size_t state_buf2_len)
{
	/* what the heck is interesting about a state? */
	const connection_t *c = st->st_connection;

	long delta = st->st_event->ev_time >= n
		? (long)(st->st_event->ev_time - n)
		: -(long)(n - st->st_event->ev_time);

	char inst[CONN_INST_BUF];
	const char *np1 = c->newest_isakmp_sa == st->st_serialno
		? "; newest ISAKMP" : "";
	const char *np2 = c->newest_ipsec_sa == st->st_serialno
		? "; newest IPSEC" : "";
	/* XXX spd-enum */
	const char *eo = c->spd.eroute_owner == st->st_serialno
		? "; eroute owner" : "";
	const char *dpd = (all && st->st_dpd && c->dpd_action != DPD_ACTION_NONE)
					  ? "; DPD active" : "";

	passert(st->st_event != 0);

	fmt_conn_instance(c, inst);

	snprintf(state_buf, state_buf_len
		, "#%lu: \"%s\"%s %s (%s); %N in %lds%s%s%s%s"
		, st->st_serialno
		, c->name, inst
		, enum_name(&state_names, st->st_state)
		, state_story[st->st_state]
		, timer_event_names, st->st_event->ev_type
		, delta
		, np1, np2, eo, dpd);

	/* print out SPIs if SAs are established */
	if (state_buf2_len != 0)
		state_buf2[0] = '\0';   /* default to empty */
	if (IS_IPSEC_SA_ESTABLISHED(st->st_state))
	{

		bool tunnel;
		char buf[SATOT_BUF*6 + 2*20 + 1];
		const char *p_end = buf + sizeof(buf);
		char *p = buf;

#       define add_said(adst, aspi, aproto) { \
			ip_said s; \
			\
			initsaid(adst, aspi, aproto, &s); \
			if (p < p_end - 1) \
			{ \
				*p++ = ' '; \
				p += satot(&s, 0, p, p_end - p) - 1; \
			} \
		}

#       define add_sa_info(st, inbound) { \
			u_int bytes; \
			time_t use_time; \
			\
			if (get_sa_info(st, inbound, &bytes, &use_time)) \
			{ \
				p += snprintf(p, p_end - p, " (%'u bytes", bytes); \
				if (bytes > 0 && use_time != UNDEFINED_TIME) \
					p += snprintf(p, p_end - p, ", %ds ago", (int)(now - use_time)); \
				p += snprintf(p, p_end - p, ")"); \
			} \
		}

		*p = '\0';
		if (st->st_ah.present)
		{
			add_said(&c->spd.that.host_addr, st->st_ah.attrs.spi, SA_AH);
			add_said(&c->spd.this.host_addr, st->st_ah.our_spi, SA_AH);
		}
		if (st->st_esp.present)
		{
			time_t now = time_monotonic(NULL);

			add_said(&c->spd.that.host_addr, st->st_esp.attrs.spi, SA_ESP);
			add_sa_info(st, FALSE);
			add_said(&c->spd.this.host_addr, st->st_esp.our_spi, SA_ESP);
			add_sa_info(st, TRUE);
		}
		if (st->st_ipcomp.present)
		{
			add_said(&c->spd.that.host_addr, st->st_ipcomp.attrs.spi, SA_COMP);
			add_said(&c->spd.this.host_addr, st->st_ipcomp.our_spi, SA_COMP);
		}
		tunnel =  st->st_ah.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL
			   || st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL
			   || st->st_ipcomp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL;
		p += snprintf(p, p_end - p, "; %s", tunnel? "tunnel":"transport");

		snprintf(state_buf2, state_buf2_len
			, "#%lu: \"%s\"%s%s"
			, st->st_serialno
			, c->name, inst
			, buf);

#       undef add_said
#       undef add_sa_info
	}
}

/*
 * sorting logic is:
 *
 *  name
 *  type
 *  instance#
 *  isakmp_sa (XXX probably wrong)
 *
 */
static int state_compare(const void *a, const void *b)
{
	const struct state *sap = *(const struct state *const *)a;
	connection_t *ca = sap->st_connection;
	const struct state *sbp = *(const struct state *const *)b;
	connection_t *cb = sbp->st_connection;

	/* DBG_log("comparing %s to %s", ca->name, cb->name); */

	return connection_compare(ca, cb);
}

void show_states_status(bool all, const char *name)
{
	time_t n = now();
	int i;
	char state_buf[LOG_WIDTH];
	char state_buf2[LOG_WIDTH];
	int count;
	struct state **array;

	/* make count of states */
	count = 0;
	for (i = 0; i < STATE_TABLE_SIZE; i++)
	{
		struct state *st;

		for (st = statetable[i]; st != NULL; st = st->st_hashchain_next)
		{
			if (name == NULL || streq(name, st->st_connection->name))
				count++;
		}
	}

	/* build the array */
	array = malloc(sizeof(struct state *)*count);
	count = 0;
	for (i = 0; i < STATE_TABLE_SIZE; i++)
	{
		struct state *st;

		for (st = statetable[i]; st != NULL; st = st->st_hashchain_next)
		{
			if (name == NULL || streq(name, st->st_connection->name))
				array[count++]=st;
		}
	}

	/* sort it! */
	qsort(array, count, sizeof(struct state *), state_compare);

	/* now print sorted results */
	for (i = 0; i < count; i++)
	{
		struct state *st;

		st = array[i];

		fmt_state(all, st, n
				  , state_buf, sizeof(state_buf)
				  , state_buf2, sizeof(state_buf2));
		whack_log(RC_COMMENT, state_buf);
		if (state_buf2[0] != '\0')
			whack_log(RC_COMMENT, state_buf2);

		/* show any associated pending Phase 2s */
		if (IS_PHASE1(st->st_state))
			show_pending_phase2(st->st_connection->host_pair, st);
	}
	if (count > 0)
		whack_log(RC_COMMENT, BLANK_FORMAT);    /* spacer */

	/* free the array */
	free(array);
}

/* Muck with high-order 16 bits of this SPI in order to make
 * the corresponding SAID unique.
 * Its low-order 16 bits hold a well-known IPCOMP CPI.
 * Oh, and remember that SPIs are stored in network order.
 * Kludge!!!  So I name it with the non-English word "uniquify".
 * If we can't find one easily, return 0 (a bad SPI,
 * no matter what order) indicating failure.
 */
ipsec_spi_t uniquify_his_cpi(ipsec_spi_t cpi, struct state *st)
{
	int tries = 0;
	int i;
	rng_t *rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);

startover:

	/* network order makes first two bytes our target */
	rng->get_bytes(rng, 2, (u_char *)&cpi);

	/* Make sure that the result is unique.
	 * Hard work.  If there is no unique value, we'll loop forever!
	 */
	for (i = 0; i < STATE_TABLE_SIZE; i++)
	{
		struct state *s;

		for (s = statetable[i]; s != NULL; s = s->st_hashchain_next)
		{
			if (s->st_ipcomp.present
			&& sameaddr(&s->st_connection->spd.that.host_addr
			  , &st->st_connection->spd.that.host_addr)
			&& cpi == s->st_ipcomp.attrs.spi)
			{
				if (++tries == 20)
				{
					rng->destroy(rng);
					return 0;   /* FAILURE */
				}
				goto startover;
			}
		}
	}
	rng->destroy(rng);
	return cpi;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * End:
 */
