/* IPsec DOI and Oakley resolution routines
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <arpa/nameser.h>       /* missing from <resolv.h> on old systems */
#include <sys/queue.h>
#include <sys/time.h>           /* for gettimeofday */

#include <freeswan.h>
#include <ipsec_policy.h>

#include <library.h>
#include <asn1/asn1.h>
#include <crypto/rngs/rng.h>

#include "constants.h"
#include "defs.h"
#include "mp_defs.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "crl.h"
#include "ca.h"
#include "certs.h"
#include "smartcard.h"
#include "connections.h"
#include "keys.h"
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "adns.h"       /* needs <resolv.h> */
#include "dnskey.h"     /* needs keys.h and adns.h */
#include "kernel.h"
#include "log.h"
#include "cookie.h"
#include "server.h"
#include "spdb.h"
#include "timer.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "whack.h"
#include "fetch.h"
#include "pkcs7.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "vendor.h"
#include "alg_info.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "nat_traversal.h"
#include "virtual.h"

/*
 * are we sending Pluto's Vendor ID?
 */
#ifdef VENDORID
#define SEND_PLUTO_VID  1
#else /* !VENDORID */
#define SEND_PLUTO_VID  0
#endif /* !VENDORID */

/*
 * are we sending an XAUTH VID?
 */
#ifdef XAUTH_VID
#define SEND_XAUTH_VID  1
#else /* !XAUTH_VID */
#define SEND_XAUTH_VID  0
#endif /* !XAUTH_VID */

/*
 * are we sending a Cisco Unity VID?
 */
#ifdef CISCO_QUIRKS
#define SEND_CISCO_UNITY_VID    1
#else /* !CISCO_QUIRKS */
#define SEND_CISCO_UNITY_VID    0
#endif /* !CISCO_QUIRKS */

/* MAGIC: perform f, a function that returns notification_t
 * and return from the ENCLOSING stf_status returning function if it fails.
 */
#define RETURN_STF_FAILURE(f) \
	{ int r = (f); if (r != NOTHING_WRONG) return STF_FAIL + r; }

/* create output HDR as replica of input HDR */
void
echo_hdr(struct msg_digest *md, bool enc, u_int8_t np)
{
	struct isakmp_hdr r_hdr = md->hdr;  /* mostly same as incoming header */

	r_hdr.isa_flags &= ~ISAKMP_FLAG_COMMIT;     /* we won't ever turn on this bit */
	if (enc)
		r_hdr.isa_flags |= ISAKMP_FLAG_ENCRYPTION;
	/* some day, we may have to set r_hdr.isa_version */
	r_hdr.isa_np = np;
	if (!out_struct(&r_hdr, &isakmp_hdr_desc, &md->reply, &md->rbody))
		impossible();   /* surely must have room and be well-formed */
}

/* Compute DH shared secret from our local secret and the peer's public value.
 * We make the leap that the length should be that of the group
 * (see quoted passage at start of ACCEPT_KE).
 */
static void compute_dh_shared(struct state *st, const chunk_t g,
							  const struct oakley_group_desc *group)
{
	MP_INT mp_g, mp_shared;
	struct timeval tv0, tv1;
	unsigned long tv_diff;

	gettimeofday(&tv0, NULL);
	passert(st->st_sec_in_use);
	n_to_mpz(&mp_g, g.ptr, g.len);
	mpz_init(&mp_shared);
	mpz_powm(&mp_shared, &mp_g, &st->st_sec, group->modulus);
	mpz_clear(&mp_g);
	free(st->st_shared.ptr);    /* happens in odd error cases */
	st->st_shared = mpz_to_n(&mp_shared, group->bytes);
	mpz_clear(&mp_shared);
	gettimeofday(&tv1, NULL);
	tv_diff=(tv1.tv_sec  - tv0.tv_sec) * 1000000 + (tv1.tv_usec - tv0.tv_usec);
	DBG(DBG_CRYPT, 
		DBG_log("compute_dh_shared(): time elapsed (%s): %ld usec"
				, enum_show(&oakley_group_names, st->st_oakley.group->group)
				, tv_diff);
	   );
	/* if took more than 200 msec ... */
	if (tv_diff > 200000) {
		loglog(RC_LOG_SERIOUS, "WARNING: compute_dh_shared(): for %s took "
						"%ld usec"
				, enum_show(&oakley_group_names, st->st_oakley.group->group)
				, tv_diff);
	}

	DBG_cond_dump_chunk(DBG_CRYPT, "DH shared secret:\n", st->st_shared);
}

/* if we haven't already done so, compute a local DH secret (st->st_sec) and
 * the corresponding public value (g).  This is emitted as a KE payload.
 */
static bool build_and_ship_KE(struct state *st, chunk_t *g,
							  const struct oakley_group_desc *group,
							  pb_stream *outs, u_int8_t np)
{
	if (!st->st_sec_in_use)
	{
		u_char tmp[LOCALSECRETSIZE];
		MP_INT mp_g;
		rng_t *rng;
		
		rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
		rng->get_bytes(rng, LOCALSECRETSIZE, tmp);
		rng->destroy(rng);
		st->st_sec_in_use = TRUE;
		n_to_mpz(&st->st_sec, tmp, LOCALSECRETSIZE);

		mpz_init(&mp_g);
		mpz_powm(&mp_g, &groupgenerator, &st->st_sec, group->modulus);
		free(g->ptr);   /* happens in odd error cases */
		*g = mpz_to_n(&mp_g, group->bytes);
		mpz_clear(&mp_g);
		DBG(DBG_CRYPT,
			DBG_dump("Local DH secret:\n", tmp, LOCALSECRETSIZE);
			DBG_dump_chunk("Public DH value sent:\n", *g));
	}
	return out_generic_chunk(np, &isakmp_keyex_desc, outs, *g, "keyex value");
}

/* accept_ke
 *
 * Check and accept DH public value (Gi or Gr) from peer's message.
 * According to RFC2409 "The Internet key exchange (IKE)" 5:
 *  The Diffie-Hellman public value passed in a KE payload, in either
 *  a phase 1 or phase 2 exchange, MUST be the length of the negotiated
 *  Diffie-Hellman group enforced, if necessary, by pre-pending the
 *  value with zeros.
 */
static notification_t accept_KE(chunk_t *dest, const char *val_name,
								const struct oakley_group_desc *gr,
								pb_stream *pbs)
{
	if (pbs_left(pbs) != gr->bytes)
	{
		loglog(RC_LOG_SERIOUS, "KE has %u byte DH public value; %u required"
			, (unsigned) pbs_left(pbs), (unsigned) gr->bytes);
		/* XXX Could send notification back */
		return INVALID_KEY_INFORMATION;
	}
	free(dest->ptr);
	*dest = chunk_create(pbs->cur, pbs_left(pbs));
	*dest = chunk_clone(*dest);
	DBG_cond_dump_chunk(DBG_CRYPT, "DH public value received:\n", *dest);
	return NOTHING_WRONG;
}

/* accept_PFS_KE
 *
 * Check and accept optional Quick Mode KE payload for PFS.
 * Extends ACCEPT_PFS to check whether KE is allowed or required.
 */
static notification_t accept_PFS_KE(struct msg_digest *md, chunk_t *dest,
									const char *val_name, const char *msg_name)
{
	struct state *st = md->st;
	struct payload_digest *const ke_pd = md->chain[ISAKMP_NEXT_KE];

	if (ke_pd == NULL)
	{
		if (st->st_pfs_group != NULL)
		{
			loglog(RC_LOG_SERIOUS, "missing KE payload in %s message", msg_name);
			return INVALID_KEY_INFORMATION;
		}
	}
	else
	{
		if (st->st_pfs_group == NULL)
		{
			loglog(RC_LOG_SERIOUS, "%s message KE payload requires a GROUP_DESCRIPTION attribute in SA"
				, msg_name);
			return INVALID_KEY_INFORMATION;
		}
		if (ke_pd->next != NULL)
		{
			loglog(RC_LOG_SERIOUS, "%s message contains several KE payloads; we accept at most one", msg_name);
			return INVALID_KEY_INFORMATION;     /* ??? */
		}
		return accept_KE(dest, val_name, st->st_pfs_group, &ke_pd->pbs);
	}
	return NOTHING_WRONG;
}

static bool build_and_ship_nonce(chunk_t *n, pb_stream *outs, u_int8_t np,
								 const char *name)
{
	rng_t *rng;

	free(n->ptr);
	*n = chunk_create(malloc(DEFAULT_NONCE_SIZE), DEFAULT_NONCE_SIZE);
	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	rng->get_bytes(rng, DEFAULT_NONCE_SIZE, n->ptr);
	rng->destroy(rng);
	return out_generic_chunk(np, &isakmp_nonce_desc, outs, *n, name);
}

static bool collect_rw_ca_candidates(struct msg_digest *md, generalName_t **top)
{
	struct connection *d = find_host_connection(&md->iface->addr
		, pluto_port, (ip_address*)NULL, md->sender_port, LEMPTY);

	for (; d != NULL; d = d->hp_next)
	{
		/* must be a road warrior connection */
		if (d->kind == CK_TEMPLATE && !(d->policy & POLICY_OPPO)
		&& d->spd.that.ca.ptr != NULL)
		{
			generalName_t *gn;
			bool new_entry = TRUE;

			for (gn = *top; gn != NULL; gn = gn->next)
			{
				if (same_dn(gn->name, d->spd.that.ca))
				{
					new_entry = FALSE;
					break;
				}
			}
			if (new_entry)
			{
				gn = malloc_thing(generalName_t);
				gn->kind = GN_DIRECTORY_NAME;
				gn->name = d->spd.that.ca;
				gn->next = *top;
				*top = gn;
			}
		}
	}
	return *top != NULL;
}

static bool build_and_ship_CR(u_int8_t type, chunk_t ca, pb_stream *outs,
							  u_int8_t np)
{
	pb_stream cr_pbs;
	struct isakmp_cr cr_hd;
	cr_hd.isacr_np = np;
	cr_hd.isacr_type = type;

	/* build CR header */
	if (!out_struct(&cr_hd, &isakmp_ipsec_cert_req_desc, outs, &cr_pbs))
		return FALSE;

	if (ca.ptr != NULL)
	{
		/* build CR body containing the distinguished name of the CA */
		if (!out_chunk(ca, &cr_pbs, "CA"))
			return FALSE;
	}
	close_output_pbs(&cr_pbs);
	return TRUE;
}

/* Send a notification to the peer.  We could decide
 * whether to send the notification, based on the type and the
 * destination, if we care to.
 */
static void send_notification(struct state *sndst, u_int16_t type,
							  struct state *encst, msgid_t msgid,
							  u_char *icookie, u_char *rcookie,
							  u_char *spi, size_t spisize, u_char protoid)
{
	u_char buffer[1024];
	pb_stream pbs, r_hdr_pbs;
	u_char *r_hashval    = NULL;  /* where in reply to jam hash value */
	u_char *r_hash_start = NULL;  /* start of what is to be hashed */

	passert((sndst) && (sndst->st_connection));

	plog("sending %snotification %s to %s:%u"
		, encst ? "encrypted " : ""
		, enum_name(&notification_names, type)
		, ip_str(&sndst->st_connection->spd.that.host_addr)
		, (unsigned)sndst->st_connection->spd.that.host_port);

	memset(buffer, 0, sizeof(buffer));
	init_pbs(&pbs, buffer, sizeof(buffer), "ISAKMP notify");

	/* HDR* */
	{
		struct isakmp_hdr hdr;

		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
		hdr.isa_np = encst ? ISAKMP_NEXT_HASH : ISAKMP_NEXT_N;
		hdr.isa_xchg = ISAKMP_XCHG_INFO;
		hdr.isa_msgid = msgid;
		hdr.isa_flags = encst ? ISAKMP_FLAG_ENCRYPTION : 0;
		if (icookie)
			memcpy(hdr.isa_icookie, icookie, COOKIE_SIZE);
		if (rcookie)
			memcpy(hdr.isa_rcookie, rcookie, COOKIE_SIZE);
		if (!out_struct(&hdr, &isakmp_hdr_desc, &pbs, &r_hdr_pbs))
			impossible();
	}

	/* HASH -- value to be filled later */
	if (encst)
	{
		pb_stream hash_pbs;
		if (!out_generic(ISAKMP_NEXT_N, &isakmp_hash_desc, &r_hdr_pbs,
			&hash_pbs))
			impossible();
		r_hashval = hash_pbs.cur;  /* remember where to plant value */
		if (!out_zero(
		encst->st_oakley.hasher->hash_digest_size, &hash_pbs, "HASH"))
			impossible();
		close_output_pbs(&hash_pbs);
		r_hash_start = r_hdr_pbs.cur; /* hash from after HASH */
	}

	/* Notification Payload */
	{
		pb_stream not_pbs;
		struct isakmp_notification isan;

		isan.isan_doi = ISAKMP_DOI_IPSEC;
		isan.isan_np = ISAKMP_NEXT_NONE;
		isan.isan_type = type;
		isan.isan_spisize = spisize;
		isan.isan_protoid = protoid;

		if (!out_struct(&isan, &isakmp_notification_desc, &r_hdr_pbs, &not_pbs)
			|| !out_raw(spi, spisize, &not_pbs, "spi"))
			impossible();
		close_output_pbs(&not_pbs);
	}

	/* calculate hash value and patch into Hash Payload */
	if (encst)
	{
		struct hmac_ctx ctx;
		hmac_init_chunk(&ctx, encst->st_oakley.hasher, encst->st_skeyid_a);
		hmac_update(&ctx, (u_char *) &msgid, sizeof(msgid_t));
		hmac_update(&ctx, r_hash_start, r_hdr_pbs.cur-r_hash_start);
		hmac_final(r_hashval, &ctx);

		DBG(DBG_CRYPT,
			DBG_log("HASH computed:");
			DBG_dump("", r_hashval, ctx.hmac_digest_size);
		)
	}

	/* Encrypt message (preserve st_iv and st_new_iv) */
	if (encst)
	{
		u_char old_iv[MAX_DIGEST_LEN];
		u_char new_iv[MAX_DIGEST_LEN];

		u_int old_iv_len = encst->st_iv_len;
		u_int new_iv_len = encst->st_new_iv_len;

		if (old_iv_len > MAX_DIGEST_LEN || new_iv_len > MAX_DIGEST_LEN)
			impossible();

		memcpy(old_iv, encst->st_iv, old_iv_len);
		memcpy(new_iv, encst->st_new_iv, new_iv_len);

		if (!IS_ISAKMP_SA_ESTABLISHED(encst->st_state))
		{
			memcpy(encst->st_ph1_iv, encst->st_new_iv, encst->st_new_iv_len);
			encst->st_ph1_iv_len = encst->st_new_iv_len;
		}
		init_phase2_iv(encst, &msgid);
		if (!encrypt_message(&r_hdr_pbs, encst))
			impossible();
			
		/* restore preserved st_iv and st_new_iv */
		memcpy(encst->st_iv, old_iv, old_iv_len);
		memcpy(encst->st_new_iv, new_iv, new_iv_len);
		encst->st_iv_len = old_iv_len;
		encst->st_new_iv_len = new_iv_len;
	}
	else
	{
		close_output_pbs(&r_hdr_pbs);
	}

	/* Send packet (preserve st_tpacket) */
	{
		chunk_t saved_tpacket = sndst->st_tpacket;

		sndst->st_tpacket = chunk_create(pbs.start, pbs_offset(&pbs));
		send_packet(sndst, "ISAKMP notify");
		sndst->st_tpacket = saved_tpacket;
	}
}

void send_notification_from_state(struct state *st, enum state_kind state,
								  u_int16_t type)
{
	struct state *p1st;

	passert(st);

	if (state == STATE_UNDEFINED)
		state = st->st_state;

	if (IS_QUICK(state))
	{
		p1st = find_phase1_state(st->st_connection, ISAKMP_SA_ESTABLISHED_STATES);
		if ((p1st == NULL) || (!IS_ISAKMP_SA_ESTABLISHED(p1st->st_state)))
		{
			loglog(RC_LOG_SERIOUS,
				"no Phase1 state for Quick mode notification");
			return;
		}
		send_notification(st, type, p1st, generate_msgid(p1st),
			st->st_icookie, st->st_rcookie, NULL, 0, PROTO_ISAKMP);
	}
	else if (IS_ISAKMP_ENCRYPTED(state) && st->st_enc_key.ptr != NULL)
	{
		send_notification(st, type, st, generate_msgid(st),
			st->st_icookie, st->st_rcookie, NULL, 0, PROTO_ISAKMP);
	}
	else
	{
		/* no ISAKMP SA established - don't encrypt notification */
		send_notification(st, type, NULL, 0,
			st->st_icookie, st->st_rcookie, NULL, 0, PROTO_ISAKMP);
	}
}

void send_notification_from_md(struct msg_digest *md, u_int16_t type)
{
	/**
	 * Create a dummy state to be able to use send_packet in
	 * send_notification
	 *
	 * we need to set:
	 *   st_connection->that.host_addr
	 *   st_connection->that.host_port
	 *   st_connection->interface
	 */
	struct state st;
	struct connection cnx;

	passert(md);

	memset(&st, 0, sizeof(st));
	memset(&cnx, 0, sizeof(cnx));
	st.st_connection = &cnx;
	cnx.spd.that.host_addr = md->sender;
	cnx.spd.that.host_port = md->sender_port;
	cnx.interface = md->iface;

	send_notification(&st, type, NULL, 0,
		md->hdr.isa_icookie, md->hdr.isa_rcookie, NULL, 0, PROTO_ISAKMP);
}

/* Send a Delete Notification to announce deletion of ISAKMP SA or
 * inbound IPSEC SAs.  Does nothing if no such SAs are being deleted.
 * Delete Notifications cannot announce deletion of outbound IPSEC/ISAKMP SAs.
 */
void send_delete(struct state *st)
{
	pb_stream reply_pbs;
	pb_stream r_hdr_pbs;
	msgid_t     msgid;
	u_char buffer[8192];
	struct state *p1st;
	ip_said said[EM_MAXRELSPIS];
	ip_said *ns = said;
	u_char
		*r_hashval,     /* where in reply to jam hash value */
		*r_hash_start;  /* start of what is to be hashed */
	bool isakmp_sa = FALSE;

	if (IS_IPSEC_SA_ESTABLISHED(st->st_state))
	{
		p1st = find_phase1_state(st->st_connection, ISAKMP_SA_ESTABLISHED_STATES);
		if (p1st == NULL)
		{
			DBG(DBG_CONTROL, DBG_log("no Phase 1 state for Delete"));
			return;
		}

		if (st->st_ah.present)
		{
			ns->spi = st->st_ah.our_spi;
			ns->dst = st->st_connection->spd.this.host_addr;
			ns->proto = PROTO_IPSEC_AH;
			ns++;
		}
		if (st->st_esp.present)
		{
			ns->spi = st->st_esp.our_spi;
			ns->dst = st->st_connection->spd.this.host_addr;
			ns->proto = PROTO_IPSEC_ESP;
			ns++;
		}

		passert(ns != said);    /* there must be some SAs to delete */
	}
	else if (IS_ISAKMP_SA_ESTABLISHED(st->st_state))
	{
		p1st = st;
		isakmp_sa = TRUE;
	}
	else
	{
		return; /* nothing to do */
	}

	msgid = generate_msgid(p1st);

	zero(buffer);
	init_pbs(&reply_pbs, buffer, sizeof(buffer), "delete msg");

	/* HDR* */
	{
		struct isakmp_hdr hdr;

		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_INFO;
		hdr.isa_msgid = msgid;
		hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
		memcpy(hdr.isa_icookie, p1st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, p1st->st_rcookie, COOKIE_SIZE);
		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_pbs, &r_hdr_pbs))
			impossible();
	}

	/* HASH -- value to be filled later */
	{
		pb_stream hash_pbs;

		if (!out_generic(ISAKMP_NEXT_D, &isakmp_hash_desc, &r_hdr_pbs, &hash_pbs))
			impossible();
		r_hashval = hash_pbs.cur;       /* remember where to plant value */
		if (!out_zero(p1st->st_oakley.hasher->hash_digest_size, &hash_pbs, "HASH(1)"))
			impossible();
		close_output_pbs(&hash_pbs);
		r_hash_start = r_hdr_pbs.cur;   /* hash from after HASH(1) */
	}

	/* Delete Payloads */
	if (isakmp_sa)
	{
		pb_stream del_pbs;
		struct isakmp_delete isad;
		u_char isakmp_spi[2*COOKIE_SIZE];

		isad.isad_doi = ISAKMP_DOI_IPSEC;
		isad.isad_np = ISAKMP_NEXT_NONE;
		isad.isad_spisize = (2 * COOKIE_SIZE);
		isad.isad_protoid = PROTO_ISAKMP;
		isad.isad_nospi = 1;

		memcpy(isakmp_spi, st->st_icookie, COOKIE_SIZE);
		memcpy(isakmp_spi+COOKIE_SIZE, st->st_rcookie, COOKIE_SIZE);

		if (!out_struct(&isad, &isakmp_delete_desc, &r_hdr_pbs, &del_pbs)
		|| !out_raw(&isakmp_spi, (2*COOKIE_SIZE), &del_pbs, "delete payload"))
			impossible();
		close_output_pbs(&del_pbs);
	}
	else
	{
		while (ns != said)
		{

			pb_stream del_pbs;
			struct isakmp_delete isad;

			ns--;
			isad.isad_doi = ISAKMP_DOI_IPSEC;
			isad.isad_np = ns == said? ISAKMP_NEXT_NONE : ISAKMP_NEXT_D;
			isad.isad_spisize = sizeof(ipsec_spi_t);
			isad.isad_protoid = ns->proto;

			isad.isad_nospi = 1;
			if (!out_struct(&isad, &isakmp_delete_desc, &r_hdr_pbs, &del_pbs)
			|| !out_raw(&ns->spi, sizeof(ipsec_spi_t), &del_pbs, "delete payload"))
				impossible();
			close_output_pbs(&del_pbs);
		}
	}

	/* calculate hash value and patch into Hash Payload */
	{
		struct hmac_ctx ctx;
		hmac_init_chunk(&ctx, p1st->st_oakley.hasher, p1st->st_skeyid_a);
		hmac_update(&ctx, (u_char *) &msgid, sizeof(msgid_t));
		hmac_update(&ctx, r_hash_start, r_hdr_pbs.cur-r_hash_start);
		hmac_final(r_hashval, &ctx);

		DBG(DBG_CRYPT,
			DBG_log("HASH(1) computed:");
			DBG_dump("", r_hashval, ctx.hmac_digest_size);
		)
	}

	/* Do a dance to avoid needing a new state object.
	 * We use the Phase 1 State.  This is the one with right
	 * IV, for one thing.
	 * The tricky bits are:
	 * - we need to preserve (save/restore) st_iv (but not st_iv_new)
	 * - we need to preserve (save/restore) st_tpacket.
	 */
	{
		u_char old_iv[MAX_DIGEST_LEN];
		chunk_t saved_tpacket = p1st->st_tpacket;

		memcpy(old_iv, p1st->st_iv, p1st->st_iv_len);
		init_phase2_iv(p1st, &msgid);

		if (!encrypt_message(&r_hdr_pbs, p1st))
			impossible();

		p1st->st_tpacket = chunk_create(reply_pbs.start, pbs_offset(&reply_pbs));
		send_packet(p1st, "delete notify");
		p1st->st_tpacket = saved_tpacket;

		/* get back old IV for this state */
		memcpy(p1st->st_iv, old_iv, p1st->st_iv_len);
	}
}

void accept_delete(struct state *st, struct msg_digest *md,
				   struct payload_digest *p)
{
	struct isakmp_delete *d = &(p->payload.delete);
	size_t sizespi;
	int i;

	if (!md->encrypted)
	{
		loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload: not encrypted");
		return;
	}

	if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state))
	{
		/* can't happen (if msg is encrypt), but just to be sure */
		loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload: "
		"ISAKMP SA not established");
		return;
	}

	if (d->isad_nospi == 0)
	{
		loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload: no SPI");
		return;
	}

	switch (d->isad_protoid)
	{
	case PROTO_ISAKMP:
		sizespi = 2 * COOKIE_SIZE;
		break;
	case PROTO_IPSEC_AH:
	case PROTO_IPSEC_ESP:
		sizespi = sizeof(ipsec_spi_t);
		break;
	case PROTO_IPCOMP:
		/* nothing interesting to delete */
		return;
	default:
		loglog(RC_LOG_SERIOUS
			, "ignoring Delete SA payload: unknown Protocol ID (%s)"
			, enum_show(&protocol_names, d->isad_protoid));
		return;
	}

	if (d->isad_spisize != sizespi)
	{
		loglog(RC_LOG_SERIOUS
			, "ignoring Delete SA payload: bad SPI size (%d) for %s"
			, d->isad_spisize, enum_show(&protocol_names, d->isad_protoid));
		return;
	}

	if (pbs_left(&p->pbs) != d->isad_nospi * sizespi)
	{
		loglog(RC_LOG_SERIOUS
			, "ignoring Delete SA payload: invalid payload size");
		return;
	}

	for (i = 0; i < d->isad_nospi; i++)
	{
		u_char *spi = p->pbs.cur + (i * sizespi);

		if (d->isad_protoid == PROTO_ISAKMP)
		{
			/**
			 * ISAKMP
			 */
			struct state *dst = find_state(spi /*iCookie*/
				, spi+COOKIE_SIZE /*rCookie*/
				, &st->st_connection->spd.that.host_addr
				, MAINMODE_MSGID);

			if (dst == NULL)
			{
				loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload: "
					"ISAKMP SA not found (maybe expired)");
			}
			else if (!same_peer_ids(st->st_connection, dst->st_connection, NULL))
			{
				/* we've not authenticated the relevant identities */
				loglog(RC_LOG_SERIOUS, "ignoring Delete SA payload: "
					"ISAKMP SA used to convey Delete has different IDs from ISAKMP SA it deletes");
			}
			else
			{
				struct connection *oldc;
				
				oldc = cur_connection;
				set_cur_connection(dst->st_connection);

				if (nat_traversal_enabled)
					nat_traversal_change_port_lookup(md, dst);

				loglog(RC_LOG_SERIOUS, "received Delete SA payload: "
					"deleting ISAKMP State #%lu", dst->st_serialno);
				delete_state(dst);
				set_cur_connection(oldc);
			}
		}
		else
		{
			/**
			 * IPSEC (ESP/AH)
			 */
			bool bogus;
			struct state *dst = find_phase2_state_to_delete(st
				, d->isad_protoid
				, *(ipsec_spi_t *)spi   /* network order */
				, &bogus);

			if (dst == NULL)
			{
				loglog(RC_LOG_SERIOUS
					   , "ignoring Delete SA payload: %s SA(0x%08lx) not found (%s)"
					   , enum_show(&protocol_names, d->isad_protoid)
					   , (unsigned long)ntohl((unsigned long)*(ipsec_spi_t *)spi)
					   , bogus ? "our SPI - bogus implementation" : "maybe expired");
			}
			else
			{
				struct connection *rc = dst->st_connection;
				struct connection *oldc;
				
				oldc = cur_connection;
				set_cur_connection(rc);

				if (nat_traversal_enabled)
					nat_traversal_change_port_lookup(md, dst);

				if (rc->newest_ipsec_sa == dst->st_serialno
				&& (rc->policy & POLICY_UP))
					{
					/* Last IPSec SA for a permanent connection that we
					 * have initiated.  Replace it in a few seconds.
					 *
					 * Useful if the other peer is rebooting.
					 */
#define DELETE_SA_DELAY  EVENT_RETRANSMIT_DELAY_0
					if (dst->st_event != NULL
					&& dst->st_event->ev_type == EVENT_SA_REPLACE
					&& dst->st_event->ev_time <= DELETE_SA_DELAY + now())
					{
						/* Patch from Angus Lees to ignore retransmited
						 * Delete SA.
						 */
						loglog(RC_LOG_SERIOUS, "received Delete SA payload: "
							"already replacing IPSEC State #%lu in %d seconds"
							, dst->st_serialno, (int)(dst->st_event->ev_time - now()));
					}
					else
					{
						loglog(RC_LOG_SERIOUS, "received Delete SA payload: "
							"replace IPSEC State #%lu in %d seconds"
							, dst->st_serialno, DELETE_SA_DELAY);
						dst->st_margin = DELETE_SA_DELAY;
						delete_event(dst);
						event_schedule(EVENT_SA_REPLACE, DELETE_SA_DELAY, dst);
					}
				}
				else
				{
					loglog(RC_LOG_SERIOUS, "received Delete SA(0x%08lx) payload: "
						   "deleting IPSEC State #%lu"
						   , (unsigned long)ntohl((unsigned long)*(ipsec_spi_t *)spi)
						   , dst->st_serialno);
					delete_state(dst);
				}

				/* reset connection */
				set_cur_connection(oldc);
			}
		}
	}
}

/* The whole message must be a multiple of 4 octets.
 * I'm not sure where this is spelled out, but look at
 * rfc2408 3.6 Transform Payload.
 * Note: it talks about 4 BYTE boundaries!
 */
void close_message(pb_stream *pbs)
{
	size_t padding =  pad_up(pbs_offset(pbs), 4);

	if (padding != 0)
		(void) out_zero(padding, pbs, "message padding");
	close_output_pbs(pbs);
}

/* Initiate an Oakley Main Mode exchange.
 * --> HDR;SA
 * Note: this is not called from demux.c
 */
static stf_status
main_outI1(int whack_sock, struct connection *c, struct state *predecessor
	, lset_t policy, unsigned long try)
{
	struct state *st = new_state();
	pb_stream reply;    /* not actually a reply, but you know what I mean */
	pb_stream rbody;

	int vids_to_send = 0;
	
	/* set up new state */
	st->st_connection = c;
	set_cur_state(st);  /* we must reset before exit */
	st->st_policy = policy & ~POLICY_IPSEC_MASK;
	st->st_whack_sock = whack_sock;
	st->st_try = try;
	st->st_state = STATE_MAIN_I1;

	/* determine how many Vendor ID payloads we will be sending */
	if (SEND_PLUTO_VID)
		vids_to_send++;
	if (SEND_CISCO_UNITY_VID)
		vids_to_send++;
	if (c->spd.this.cert.type == CERT_PGP)
		vids_to_send++;
	if (SEND_XAUTH_VID)
		vids_to_send++;
	/* always send DPD Vendor ID */
		vids_to_send++;
	if (nat_traversal_enabled)
		vids_to_send++;

   get_cookie(TRUE, st->st_icookie, COOKIE_SIZE, &c->spd.that.host_addr);

	insert_state(st);   /* needs cookies, connection, and msgid (0) */

	if (HAS_IPSEC_POLICY(policy))
		add_pending(dup_any(whack_sock), st, c, policy, 1
			, predecessor == NULL? SOS_NOBODY : predecessor->st_serialno);

	if (predecessor == NULL)
		plog("initiating Main Mode");
	else
		plog("initiating Main Mode to replace #%lu", predecessor->st_serialno);

	/* set up reply */
	init_pbs(&reply, reply_buffer, sizeof(reply_buffer), "reply packet");

	/* HDR out */
	{
		struct isakmp_hdr hdr;

		zero(&hdr);     /* default to 0 */
		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_SA;
		hdr.isa_xchg = ISAKMP_XCHG_IDPROT;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		/* R-cookie, flags and MessageID are left zero */

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
		{
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* SA out */
	{
		u_char *sa_start = rbody.cur;

		if (!out_sa(&rbody, &oakley_sadb, st, TRUE
		, vids_to_send-- ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE))
		{
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}

		/* save initiator SA for later HASH */
		passert(st->st_p1isa.ptr == NULL);      /* no leak!  (MUST be first time) */
		st->st_p1isa = chunk_create(sa_start, rbody.cur - sa_start);
		st->st_p1isa = chunk_clone(st->st_p1isa);
	}

	/* if enabled send Pluto Vendor ID */
	if (SEND_PLUTO_VID)
	{
		if (!out_vendorid(vids_to_send-- ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE
		, &rbody, VID_STRONGSWAN))
		{
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* if enabled send Cisco Unity Vendor ID */
	if (SEND_CISCO_UNITY_VID)
	{
		if (!out_vendorid(vids_to_send-- ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE
		, &rbody, VID_CISCO_UNITY))
		{
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}
	/* if we  have an OpenPGP certificate we assume an
	 * OpenPGP peer and have to send the Vendor ID
	 */
	if (c->spd.this.cert.type == CERT_PGP)
	{
		if (!out_vendorid(vids_to_send-- ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE
		, &rbody, VID_OPENPGP))
		{
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* Announce our ability to do eXtended AUTHentication to the peer */
	if (SEND_XAUTH_VID)
	{
		if (!out_vendorid(vids_to_send-- ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE
		, &rbody, VID_MISC_XAUTH))
		{
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* Announce our ability to do Dead Peer Detection to the peer */
	{
		if (!out_vendorid(vids_to_send-- ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE
		, &rbody, VID_MISC_DPD))
		{
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	if (nat_traversal_enabled)
	{
		/* Add supported NAT-Traversal VID */
		if (!nat_traversal_add_vid(vids_to_send-- ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE
		, &rbody))
		{
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	close_message(&rbody);
	close_output_pbs(&reply);
	st->st_tpacket = chunk_create(reply.start, pbs_offset(&reply));
	st->st_tpacket = chunk_clone(st->st_tpacket);

	/* Transmit */

	send_packet(st, "main_outI1");

	/* Set up a retransmission event, half a minute henceforth */
	delete_event(st);
	event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

	if (predecessor != NULL)
	{
		update_pending(predecessor, st);
		whack_log(RC_NEW_STATE + STATE_MAIN_I1
			, "%s: initiate, replacing #%lu"
			, enum_name(&state_names, st->st_state)
			, predecessor->st_serialno);
	}
	else
	{
		whack_log(RC_NEW_STATE + STATE_MAIN_I1
			, "%s: initiate", enum_name(&state_names, st->st_state));
	}
	reset_cur_state();
	return STF_OK;
}

void ipsecdoi_initiate(int whack_sock, struct connection *c, lset_t policy,
					   unsigned long try, so_serial_t replacing)
{
	/* If there's already an ISAKMP SA established, use that and
	 * go directly to Quick Mode.  We are even willing to use one
	 * that is still being negotiated, but only if we are the Initiator
	 * (thus we can be sure that the IDs are not going to change;
	 * other issues around intent might matter).
	 * Note: there is no way to initiate with a Road Warrior.
	 */
	struct state *st = find_phase1_state(c
		, ISAKMP_SA_ESTABLISHED_STATES | PHASE1_INITIATOR_STATES);

	if (st == NULL)
	{
		(void) main_outI1(whack_sock, c, NULL, policy, try);
	}
	else if (HAS_IPSEC_POLICY(policy))
	{
		if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state))
		{
			/* leave our Phase 2 negotiation pending */
			add_pending(whack_sock, st, c, policy, try, replacing);
		}
		else
		{
			/* ??? we assume that peer_nexthop_sin isn't important:
			 * we already have it from when we negotiated the ISAKMP SA!
			 * It isn't clear what to do with the error return.
			 */
			(void) quick_outI1(whack_sock, st, c, policy, try, replacing);
		}
	}
	else
	{
		close_any(whack_sock);
	}
}

/* Replace SA with a fresh one that is similar
 *
 * Shares some logic with ipsecdoi_initiate, but not the same!
 * - we must not reuse the ISAKMP SA if we are trying to replace it!
 * - if trying to replace IPSEC SA, use ipsecdoi_initiate to build
 *   ISAKMP SA if needed.
 * - duplicate whack fd, if live.
 * Does not delete the old state -- someone else will do that.
 */
void ipsecdoi_replace(struct state *st, unsigned long try)
{
	int whack_sock = dup_any(st->st_whack_sock);
	lset_t policy = st->st_policy;

	if (IS_PHASE1(st->st_state))
	{
		passert(!HAS_IPSEC_POLICY(policy));
		(void) main_outI1(whack_sock, st->st_connection, st, policy, try);
	}
	else
	{
		/* Add features of actual old state to policy.  This ensures
		 * that rekeying doesn't downgrade security.  I admit that
		 * this doesn't capture everything.
		 */
		if (st->st_pfs_group != NULL)
			policy |= POLICY_PFS;
		if (st->st_ah.present)
		{
			policy |= POLICY_AUTHENTICATE;
			if (st->st_ah.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
				policy |= POLICY_TUNNEL;
		}
		if (st->st_esp.present && st->st_esp.attrs.transid != ESP_NULL)
		{
			policy |= POLICY_ENCRYPT;
			if (st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
				policy |= POLICY_TUNNEL;
		}
		if (st->st_ipcomp.present)
		{
			policy |= POLICY_COMPRESS;
			if (st->st_ipcomp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
				policy |= POLICY_TUNNEL;
		}
		passert(HAS_IPSEC_POLICY(policy));
		ipsecdoi_initiate(whack_sock, st->st_connection, policy, try
			, st->st_serialno);
	}
}

/* SKEYID for preshared keys.
 * See draft-ietf-ipsec-ike-01.txt 4.1
 */
static bool skeyid_preshared(struct state *st)
{
	const chunk_t *pss = get_preshared_secret(st->st_connection);

	if (pss == NULL)
	{
		loglog(RC_LOG_SERIOUS, "preshared secret disappeared!");
		return FALSE;
	}
	else
	{
		struct hmac_ctx ctx;

		hmac_init_chunk(&ctx, st->st_oakley.hasher, *pss);
		hmac_update_chunk(&ctx, st->st_ni);
		hmac_update_chunk(&ctx, st->st_nr);
		hmac_final_chunk(st->st_skeyid, "st_skeyid in skeyid_preshared()", &ctx);
		return TRUE;
	}
}

static bool
skeyid_digisig(struct state *st)
{
	struct hmac_ctx ctx;
	chunk_t nir;

	/* We need to hmac_init with the concatenation of Ni_b and Nr_b,
	 * so we have to build a temporary concatentation.
	 */
	nir.len = st->st_ni.len + st->st_nr.len;
	nir.ptr = malloc(nir.len);
	memcpy(nir.ptr, st->st_ni.ptr, st->st_ni.len);
	memcpy(nir.ptr+st->st_ni.len, st->st_nr.ptr, st->st_nr.len);
	hmac_init_chunk(&ctx, st->st_oakley.hasher, nir);
	free(nir.ptr);

	hmac_update_chunk(&ctx, st->st_shared);
	hmac_final_chunk(st->st_skeyid, "st_skeyid in skeyid_digisig()", &ctx);
	return TRUE;
}

/* Generate the SKEYID_* and new IV
 * See draft-ietf-ipsec-ike-01.txt 4.1
 */
static bool generate_skeyids_iv(struct state *st)
{
	/* Generate the SKEYID */
	switch (st->st_oakley.auth)
	{
		case OAKLEY_PRESHARED_KEY:
		case XAUTHInitPreShared:
		case XAUTHRespPreShared:
			if (!skeyid_preshared(st))
				return FALSE;
			break;

		case OAKLEY_RSA_SIG:
		case XAUTHInitRSA:
		case XAUTHRespRSA:
			if (!skeyid_digisig(st))
				return FALSE;
			break;

		case OAKLEY_DSS_SIG:
			/* XXX */

		case OAKLEY_RSA_ENC:
		case OAKLEY_RSA_ENC_REV:
		case OAKLEY_ELGAMAL_ENC:
		case OAKLEY_ELGAMAL_ENC_REV:
			/* XXX */

		default:
			bad_case(st->st_oakley.auth);
	}

	/* generate SKEYID_* from SKEYID */
	{
		struct hmac_ctx ctx;

		hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid);

		/* SKEYID_D */
		hmac_update_chunk(&ctx, st->st_shared);
		hmac_update(&ctx, st->st_icookie, COOKIE_SIZE);
		hmac_update(&ctx, st->st_rcookie, COOKIE_SIZE);
		hmac_update(&ctx, "\0", 1);
		hmac_final_chunk(st->st_skeyid_d, "st_skeyid_d in generate_skeyids_iv()", &ctx);

		/* SKEYID_A */
		hmac_reinit(&ctx);
		hmac_update_chunk(&ctx, st->st_skeyid_d);
		hmac_update_chunk(&ctx, st->st_shared);
		hmac_update(&ctx, st->st_icookie, COOKIE_SIZE);
		hmac_update(&ctx, st->st_rcookie, COOKIE_SIZE);
		hmac_update(&ctx, "\1", 1);
		hmac_final_chunk(st->st_skeyid_a, "st_skeyid_a in generate_skeyids_iv()", &ctx);

		/* SKEYID_E */
		hmac_reinit(&ctx);
		hmac_update_chunk(&ctx, st->st_skeyid_a);
		hmac_update_chunk(&ctx, st->st_shared);
		hmac_update(&ctx, st->st_icookie, COOKIE_SIZE);
		hmac_update(&ctx, st->st_rcookie, COOKIE_SIZE);
		hmac_update(&ctx, "\2", 1);
		hmac_final_chunk(st->st_skeyid_e, "st_skeyid_e in generate_skeyids_iv()", &ctx);
	}

	/* generate IV */
	{
		union hash_ctx hash_ctx;
		const struct hash_desc *h = st->st_oakley.hasher;

		st->st_new_iv_len = h->hash_digest_size;
		passert(st->st_new_iv_len <= sizeof(st->st_new_iv));

		DBG(DBG_CRYPT,
			DBG_dump_chunk("DH_i:", st->st_gi);
			DBG_dump_chunk("DH_r:", st->st_gr);
		);
		h->hash_init(&hash_ctx);
		h->hash_update(&hash_ctx, st->st_gi.ptr, st->st_gi.len);
		h->hash_update(&hash_ctx, st->st_gr.ptr, st->st_gr.len);
		h->hash_final(st->st_new_iv, &hash_ctx);
	}

	/* Oakley Keying Material
	 * Derived from Skeyid_e: if it is not big enough, generate more
	 * using the PRF.
	 * See RFC 2409 "IKE" Appendix B
	 */
	{
		/* const size_t keysize = st->st_oakley.encrypter->keydeflen/BITS_PER_BYTE; */
		const size_t keysize = st->st_oakley.enckeylen/BITS_PER_BYTE;
		u_char keytemp[MAX_OAKLEY_KEY_LEN + MAX_DIGEST_LEN];
		u_char *k = st->st_skeyid_e.ptr;

		if (keysize > st->st_skeyid_e.len)
		{
			struct hmac_ctx ctx;
			size_t i = 0;

			hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid_e);
			hmac_update(&ctx, "\0", 1);
			for (;;)
			{
				hmac_final(&keytemp[i], &ctx);
				i += ctx.hmac_digest_size;
				if (i >= keysize)
					break;
				hmac_reinit(&ctx);
				hmac_update(&ctx, &keytemp[i - ctx.hmac_digest_size], ctx.hmac_digest_size);
			}
			k = keytemp;
		}
		free(st->st_enc_key.ptr);
		st->st_enc_key = chunk_create(k, keysize);
		st->st_enc_key = chunk_clone(st->st_enc_key);
	}

	DBG(DBG_CRYPT,
		DBG_dump_chunk("Skeyid:  ", st->st_skeyid);
		DBG_dump_chunk("Skeyid_d:", st->st_skeyid_d);
		DBG_dump_chunk("Skeyid_a:", st->st_skeyid_a);
		DBG_dump_chunk("Skeyid_e:", st->st_skeyid_e);
		DBG_dump_chunk("enc key:", st->st_enc_key);
		DBG_dump("IV:", st->st_new_iv, st->st_new_iv_len));
	return TRUE;
}

/* Generate HASH_I or HASH_R for ISAKMP Phase I.
 * This will *not* generate other hash payloads (eg. Phase II or Quick Mode,
 * New Group Mode, or ISAKMP Informational Exchanges).
 * If the hashi argument is TRUE, generate HASH_I; if FALSE generate HASH_R.
 * If hashus argument is TRUE, we're generating a hash for our end.
 * See RFC2409 IKE 5.
 *
 * Generating the SIG_I and SIG_R for DSS is an odd perversion of this:
 * Most of the logic is the same, but SHA-1 is used in place of HMAC-whatever.
 * The extensive common logic is embodied in main_mode_hash_body().
 * See draft-ietf-ipsec-ike-01.txt 4.1 and 6.1.1.2
 */

typedef void (*hash_update_t)(union hash_ctx *, const u_char *, size_t) ;

static void main_mode_hash_body(struct state *st, bool hashi,
								const pb_stream *idpl, union hash_ctx *ctx,
			void (*hash_update_void)(void *, const u_char *input, size_t))
{
#define HASH_UPDATE_T (union hash_ctx *, const u_char *input, unsigned int len)
	hash_update_t hash_update=(hash_update_t)  hash_update_void;
#if 0   /* if desperate to debug hashing */
#   define hash_update(ctx, input, len) { \
		DBG_dump("hash input", input, len); \
		(hash_update)(ctx, input, len); \
		}
#endif

#   define hash_update_chunk(ctx, ch) hash_update((ctx), (ch).ptr, (ch).len)

	if (hashi)
	{
		hash_update_chunk(ctx, st->st_gi);
		hash_update_chunk(ctx, st->st_gr);
		hash_update(ctx, st->st_icookie, COOKIE_SIZE);
		hash_update(ctx, st->st_rcookie, COOKIE_SIZE);
	}
	else
	{
		hash_update_chunk(ctx, st->st_gr);
		hash_update_chunk(ctx, st->st_gi);
		hash_update(ctx, st->st_rcookie, COOKIE_SIZE);
		hash_update(ctx, st->st_icookie, COOKIE_SIZE);
	}

	DBG(DBG_CRYPT, DBG_log("hashing %lu bytes of SA"
		, (unsigned long) (st->st_p1isa.len - sizeof(struct isakmp_generic))));

	/* SA_b */
	hash_update(ctx, st->st_p1isa.ptr + sizeof(struct isakmp_generic)
		, st->st_p1isa.len - sizeof(struct isakmp_generic));

	/* Hash identification payload, without generic payload header.
	 * We used to reconstruct ID Payload for this purpose, but now
	 * we use the bytes as they appear on the wire to avoid
	 * "spelling problems".
	 */
	hash_update(ctx
		, idpl->start + sizeof(struct isakmp_generic)
		, pbs_offset(idpl) - sizeof(struct isakmp_generic));

#   undef hash_update_chunk
#   undef hash_update
}

static size_t   /* length of hash */
main_mode_hash(struct state *st, u_char *hash_val, bool hashi,
			   const pb_stream *idpl)
{
	struct hmac_ctx ctx;

	hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid);
	main_mode_hash_body(st, hashi, idpl, &ctx.hash_ctx, ctx.h->hash_update);
	hmac_final(hash_val, &ctx);
	return ctx.hmac_digest_size;
}

#if 0   /* only needed for DSS */
static void
main_mode_sha1(struct state *st
, u_char *hash_val      /* resulting bytes */
, size_t *hash_len      /* length of hash */
, bool hashi    /* Initiator? */
, const pb_stream *idpl)        /* ID payload, as PBS */
{
	union hash_ctx ctx;

	SHA1Init(&ctx.ctx_sha1);
	SHA1Update(&ctx.ctx_sha1, st->st_skeyid.ptr, st->st_skeyid.len);
	*hash_len = SHA1_DIGEST_SIZE;
	main_mode_hash_body(st, hashi, idpl, &ctx
		, (void (*)(union hash_ctx *, const u_char *, unsigned int))&SHA1Update);
	SHA1Final(hash_val, &ctx.ctx_sha1);
}
#endif

/* Create an RSA signature of a hash.
 * Poorly specified in draft-ietf-ipsec-ike-01.txt 6.1.1.2.
 * Use PKCS#1 version 1.5 encryption of hash (called
 * RSAES-PKCS1-V1_5) in PKCS#2.
 */
static size_t RSA_sign_hash(struct connection *c, u_char sig_val[RSA_MAX_OCTETS],
							const u_char *hash_val, size_t hash_len)
{
	size_t sz = 0;
	smartcard_t *sc = c->spd.this.sc;

	if (sc == NULL)             /* no smartcard */
	{
		const struct RSA_private_key *k = get_RSA_private_key(c);

		if (k == NULL)
			return 0;   /* failure: no key to use */

		sz = k->pub.k;
		passert(RSA_MIN_OCTETS <= sz && 4 + hash_len < sz && sz <= RSA_MAX_OCTETS);
		sign_hash(k, hash_val, hash_len, sig_val, sz);
	}
	else if (sc->valid) /* if valid pin then sign hash on the smartcard */
	{
		lock_certs_and_keys("RSA_sign_hash");
		if (!scx_establish_context(sc) || !scx_login(sc))
		{
			scx_release_context(sc);
			unlock_certs_and_keys("RSA_sign_hash");
			return 0;
		}

		sz = scx_get_keylength(sc);
		if (sz == 0)
		{
			plog("failed to get keylength from smartcard");
			scx_release_context(sc);
			unlock_certs_and_keys("RSA_sign_hash");
			return 0;
		}

		DBG(DBG_CONTROL | DBG_CRYPT,
			DBG_log("signing hash with RSA key from smartcard (slot: %d, id: %s)"
				, (int)sc->slot, sc->id)
		)
		sz = scx_sign_hash(sc, hash_val, hash_len, sig_val, sz) ? sz : 0;
		if (!pkcs11_keep_state)
			scx_release_context(sc);
		unlock_certs_and_keys("RSA_sign_hash");
	}
	return sz;
}

/* Check a Main Mode RSA Signature against computed hash using RSA public key k.
 *
 * As a side effect, on success, the public key is copied into the
 * state object to record the authenticator.
 *
 * Can fail because wrong public key is used or because hash disagrees.
 * We distinguish because diagnostics should also.
 *
 * The result is NULL if the Signature checked out.
 * Otherwise, the first character of the result indicates
 * how far along failure occurred.  A greater character signifies
 * greater progress.
 *
 * Classes:
 * 0    reserved for caller
 * 1    SIG length doesn't match key length -- wrong key
 * 2-8  malformed ECB after decryption -- probably wrong key
 * 9    decrypted hash != computed hash -- probably correct key
 *
 * Although the math should be the same for generating and checking signatures,
 * it is not: the knowledge of the private key allows more efficient (i.e.
 * different) computation for encryption.
 */
static err_t try_RSA_signature(const u_char hash_val[MAX_DIGEST_LEN],
							   size_t hash_len, const pb_stream *sig_pbs,
							   pubkey_t *kr, struct state *st)
{
	const u_char *sig_val = sig_pbs->cur;
	size_t sig_len = pbs_left(sig_pbs);
	u_char s[RSA_MAX_OCTETS];   /* for decrypted sig_val */
	u_char *hash_in_s = &s[sig_len - hash_len];
	const struct RSA_public_key *k = &kr->u.rsa;

	/* decrypt the signature -- reversing RSA_sign_hash */
	if (sig_len != k->k)
	{
		/* XXX notification: INVALID_KEY_INFORMATION */
		return "1" "SIG length does not match public key length";
	}

	/* actual exponentiation; see PKCS#1 v2.0 5.1 */
	{
		chunk_t temp_s;
		mpz_t c;

		n_to_mpz(c, sig_val, sig_len);
		mpz_powm(c, c, &k->e, &k->n);

		temp_s = mpz_to_n(c, sig_len);  /* back to octets */
		memcpy(s, temp_s.ptr, sig_len);
		free(temp_s.ptr);
		mpz_clear(c);
	}

	/* sanity check on signature: see if it matches
	 * PKCS#1 v1.5 8.1 encryption-block formatting
	 */
	{
		err_t ugh = NULL;

		if (s[0] != 0x00)
			ugh = "2" "no leading 00";
		else if (hash_in_s[-1] != 0x00)
			ugh = "3" "00 separator not present";
		else if (s[1] == 0x01)
		{
			const u_char *p;

			for (p = &s[2]; p != hash_in_s - 1; p++)
			{
				if (*p != 0xFF)
				{
					ugh = "4" "invalid Padding String";
					break;
				}
			}
		}
		else if (s[1] == 0x02)
		{
			const u_char *p;

			for (p = &s[2]; p != hash_in_s - 1; p++)
			{
				if (*p == 0x00)
				{
					ugh = "5" "invalid Padding String";
					break;
				}
			}
		}
		else
			ugh = "6" "Block Type not 01 or 02";

		if (ugh != NULL)
		{
			/* note: it might be a good idea to make sure that
			 * an observer cannot tell what kind of failure happened.
			 * I don't know what this means in practice.
			 */
			/* We probably selected the wrong public key for peer:
			 * SIG Payload decrypted into malformed ECB
			 */
			/* XXX notification: INVALID_KEY_INFORMATION */
			return ugh;
		}
	}

	/* We have the decoded hash: see if it matches. */
	if (memcmp(hash_val, hash_in_s, hash_len) != 0)
	{
		/* good: header, hash, signature, and other payloads well-formed
		 * good: we could find an RSA Sig key for the peer.
		 * bad: hash doesn't match
		 * Guess: sides disagree about key to be used.
		 */
		DBG_cond_dump(DBG_CRYPT, "decrypted SIG", s, sig_len);
		DBG_cond_dump(DBG_CRYPT, "computed HASH", hash_val, hash_len);
		/* XXX notification: INVALID_HASH_INFORMATION */
		return "9" "authentication failure: received SIG does not match computed HASH, but message is well-formed";
	}

	/* Success: copy successful key into state.
	 * There might be an old one if we previously aborted this
	 * state transition.
	 */
	unreference_key(&st->st_peer_pubkey);
	st->st_peer_pubkey = reference_key(kr);

	return NULL;    /* happy happy */
}

/* Check signature against all RSA public keys we can find.
 * If we need keys from DNS KEY records, and they haven't been fetched,
 * return STF_SUSPEND to ask for asynch DNS lookup.
 *
 * Note: parameter keys_from_dns contains results of DNS lookup for key
 * or is NULL indicating lookup not yet tried.
 *
 * take_a_crack is a helper function.  Mostly forensic.
 * If only we had coroutines.
 */
struct tac_state {
	/* RSA_check_signature's args that take_a_crack needs */
	struct state *st;
	const u_char *hash_val;
	size_t hash_len;
	const pb_stream *sig_pbs;

	/* state carried between calls */
	err_t best_ugh;     /* most successful failure */
	int tried_cnt;      /* number of keys tried */
	char tried[50];     /* keyids of tried public keys */
	char *tn;   /* roof of tried[] */
};

static bool take_a_crack(struct tac_state *s, pubkey_t *kr,
						 const char *story USED_BY_DEBUG)
{
	err_t ugh = try_RSA_signature(s->hash_val, s->hash_len, s->sig_pbs
		, kr, s->st);
	const struct RSA_public_key *k = &kr->u.rsa;

	s->tried_cnt++;
	if (ugh == NULL)
	{
		DBG(DBG_CRYPT | DBG_CONTROL
			, DBG_log("an RSA Sig check passed with *%s [%s]"
				, k->keyid, story));
		return TRUE;
	}
	else
	{
		DBG(DBG_CRYPT
			, DBG_log("an RSA Sig check failure %s with *%s [%s]"
				, ugh + 1, k->keyid, story));
		if (s->best_ugh == NULL || s->best_ugh[0] < ugh[0])
			s->best_ugh = ugh;
		if (ugh[0] > '0'
		&& s->tn - s->tried + KEYID_BUF + 2 < (ptrdiff_t)sizeof(s->tried))
		{
			strcpy(s->tn, " *");
			strcpy(s->tn + 2, k->keyid);
			s->tn += strlen(s->tn);
		}
		return FALSE;
	}
}

static stf_status RSA_check_signature(const struct id* peer, struct state *st,
									  const u_char hash_val[MAX_DIGEST_LEN],
									  size_t hash_len, const pb_stream *sig_pbs,
#ifdef USE_KEYRR
									  const pubkey_list_t *keys_from_dns,
#endif /* USE_KEYRR */
									  const struct gw_info *gateways_from_dns)
{
	const struct connection *c = st->st_connection;
	struct tac_state s;
	err_t dns_ugh = NULL;

	s.st = st;
	s.hash_val = hash_val;
	s.hash_len = hash_len;
	s.sig_pbs = sig_pbs;

	s.best_ugh = NULL;
	s.tried_cnt = 0;
	s.tn = s.tried;

	/* try all gateway records hung off c */
	if (c->policy & POLICY_OPPO)
	{
		struct gw_info *gw;

		for (gw = c->gw_info; gw != NULL; gw = gw->next)
		{
			/* only consider entries that have a key and are for our peer */
			if (gw->gw_key_present
			&& same_id(&gw->gw_id, &c->spd.that.id)
			&& take_a_crack(&s, gw->key, "key saved from DNS TXT"))
				return STF_OK;
		}
	}

	/* try all appropriate Public keys */
	{
		pubkey_list_t *p, **pp;

		pp = &pubkeys;

		for (p = pubkeys; p != NULL; p = *pp)
		{
			pubkey_t *key = p->key;

			if (key->alg == PUBKEY_ALG_RSA && same_id(peer, &key->id))
			{
				time_t now = time(NULL);

				/* check if found public key has expired */
				if (key->until_time != UNDEFINED_TIME && key->until_time < now)
				{
					loglog(RC_LOG_SERIOUS,
						"cached RSA public key has expired and has been deleted");
					*pp = free_public_keyentry(p);
					continue; /* continue with next public key */
				}

				if (take_a_crack(&s, key, "preloaded key"))
				return STF_OK;
			}
			pp = &p->next;
		}
   }

	/* if no key was found (evidenced by best_ugh == NULL)
	 * and that side of connection is key_from_DNS_on_demand
	 * then go search DNS for keys for peer.
	 */
	if (s.best_ugh == NULL && c->spd.that.key_from_DNS_on_demand)
	{
		if (gateways_from_dns != NULL)
		{
			/* TXT keys */
			const struct gw_info *gwp;

			for (gwp = gateways_from_dns; gwp != NULL; gwp = gwp->next)
				if (gwp->gw_key_present
				&& take_a_crack(&s, gwp->key, "key from DNS TXT"))
					return STF_OK;
		}
#ifdef USE_KEYRR
		else if (keys_from_dns != NULL)
		{
			/* KEY keys */
			const pubkey_list_t *kr;

			for (kr = keys_from_dns; kr != NULL; kr = kr->next)
				if (kr->key->alg == PUBKEY_ALG_RSA
				&& take_a_crack(&s, kr->key, "key from DNS KEY"))
					return STF_OK;
		}
#endif /* USE_KEYRR */
		else
		{
			/* nothing yet: ask for asynch DNS lookup */
			return STF_SUSPEND;
		}
	}

	/* no acceptable key was found: diagnose */
	{
		char id_buf[BUF_LEN];   /* arbitrary limit on length of ID reported */

		(void) idtoa(peer, id_buf, sizeof(id_buf));

		if (s.best_ugh == NULL)
		{
			if (dns_ugh == NULL)
				loglog(RC_LOG_SERIOUS, "no RSA public key known for '%s'"
					, id_buf);
			else
				loglog(RC_LOG_SERIOUS, "no RSA public key known for '%s'"
					"; DNS search for KEY failed (%s)"
					, id_buf, dns_ugh);

			/* ??? is this the best code there is? */
			return STF_FAIL + INVALID_KEY_INFORMATION;
		}

		if (s.best_ugh[0] == '9')
		{
			loglog(RC_LOG_SERIOUS, "%s", s.best_ugh + 1);
			/* XXX Could send notification back */
			return STF_FAIL + INVALID_HASH_INFORMATION;
		}
		else
		{
			if (s.tried_cnt == 1)
			{
				loglog(RC_LOG_SERIOUS
					, "Signature check (on %s) failed (wrong key?); tried%s"
					, id_buf, s.tried);
				DBG(DBG_CONTROL,
					DBG_log("public key for %s failed:"
						" decrypted SIG payload into a malformed ECB (%s)"
						, id_buf, s.best_ugh + 1));
			}
			else
			{
				loglog(RC_LOG_SERIOUS
					, "Signature check (on %s) failed:"
					  " tried%s keys but none worked."
					, id_buf, s.tried);
				DBG(DBG_CONTROL,
					DBG_log("all %d public keys for %s failed:"
						" best decrypted SIG payload into a malformed ECB (%s)"
						, s.tried_cnt, id_buf, s.best_ugh + 1));
			}
			return STF_FAIL + INVALID_KEY_INFORMATION;
		}
	}
}

static notification_t accept_nonce(struct msg_digest *md, chunk_t *dest,
								   const char *name)
{
	pb_stream *nonce_pbs = &md->chain[ISAKMP_NEXT_NONCE]->pbs;
	size_t len = pbs_left(nonce_pbs);

	if (len < MINIMUM_NONCE_SIZE || MAXIMUM_NONCE_SIZE < len)
	{
		loglog(RC_LOG_SERIOUS, "%s length not between %d and %d"
			, name , MINIMUM_NONCE_SIZE, MAXIMUM_NONCE_SIZE);
		return PAYLOAD_MALFORMED;       /* ??? */
	}
	free(dest->ptr);
	*dest = chunk_create(nonce_pbs->cur, len);
	*dest = chunk_clone(*dest);
	return NOTHING_WRONG;
}

/* encrypt message, sans fixed part of header
 * IV is fetched from st->st_new_iv and stored into st->st_iv.
 * The theory is that there will be no "backing out", so we commit to IV.
 * We also close the pbs.
 */
bool
encrypt_message(pb_stream *pbs, struct state *st)
{
	const struct encrypt_desc *e = st->st_oakley.encrypter;
	u_int8_t *enc_start = pbs->start + sizeof(struct isakmp_hdr);
	size_t enc_len = pbs_offset(pbs) - sizeof(struct isakmp_hdr);

	DBG_cond_dump(DBG_CRYPT | DBG_RAW, "encrypting:\n", enc_start, enc_len);

	/* Pad up to multiple of encryption blocksize.
	 * See the description associated with the definition of
	 * struct isakmp_hdr in packet.h.
	 */
	{
		size_t padding = pad_up(enc_len, e->enc_blocksize);

		if (padding != 0)
		{
			if (!out_zero(padding, pbs, "encryption padding"))
				return FALSE;
			enc_len += padding;
		}
	}

	DBG(DBG_CRYPT, DBG_log("encrypting using %s", enum_show(&oakley_enc_names, st->st_oakley.encrypt)));

	/* e->crypt(TRUE, enc_start, enc_len, st); */
	crypto_cbc_encrypt(e, TRUE, enc_start, enc_len, st);

	update_iv(st);
	DBG_cond_dump(DBG_CRYPT, "next IV:", st->st_iv, st->st_iv_len);
	close_message(pbs);
	return TRUE;
}

/* Compute HASH(1), HASH(2) of Quick Mode.
 * HASH(1) is part of Quick I1 message.
 * HASH(2) is part of Quick R1 message.
 * Used by: quick_outI1, quick_inI1_outR1 (twice), quick_inR1_outI2
 * (see RFC 2409 "IKE" 5.5, pg. 18 or draft-ietf-ipsec-ike-01.txt 6.2 pg 25)
 */
static size_t quick_mode_hash12(u_char *dest, const u_char *start,
								const u_char *roof, const struct state *st,
								const msgid_t *msgid, bool hash2)
{
	struct hmac_ctx ctx;

#if 0   /* if desperate to debug hashing */
#   define hmac_update(ctx, ptr, len) { \
		DBG_dump("hash input", (ptr), (len)); \
		(hmac_update)((ctx), (ptr), (len)); \
	}
	DBG_dump("hash key", st->st_skeyid_a.ptr, st->st_skeyid_a.len);
#endif
	hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid_a);
	hmac_update(&ctx, (const void *) msgid, sizeof(msgid_t));
	if (hash2)
		hmac_update_chunk(&ctx, st->st_ni);     /* include Ni_b in the hash */
	hmac_update(&ctx, start, roof-start);
	hmac_final(dest, &ctx);

	DBG(DBG_CRYPT,
		DBG_log("HASH(%d) computed:", hash2 + 1);
		DBG_dump("", dest, ctx.hmac_digest_size));
	return ctx.hmac_digest_size;
#   undef hmac_update
}

/* Compute HASH(3) in Quick Mode (part of Quick I2 message).
 * Used by: quick_inR1_outI2, quick_inI2
 * See RFC2409 "The Internet Key Exchange (IKE)" 5.5.
 * NOTE: this hash (unlike HASH(1) and HASH(2)) ONLY covers the
 * Message ID and Nonces.  This is a mistake.
 */
static size_t quick_mode_hash3(u_char *dest, struct state *st)
{
	struct hmac_ctx ctx;

	hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid_a);
	hmac_update(&ctx, "\0", 1);
	hmac_update(&ctx, (u_char *) &st->st_msgid, sizeof(st->st_msgid));
	hmac_update_chunk(&ctx, st->st_ni);
	hmac_update_chunk(&ctx, st->st_nr);
	hmac_final(dest, &ctx);
	DBG_cond_dump(DBG_CRYPT, "HASH(3) computed:", dest, ctx.hmac_digest_size);
	return ctx.hmac_digest_size;
}

/* Compute Phase 2 IV.
 * Uses Phase 1 IV from st_iv; puts result in st_new_iv.
 */
void init_phase2_iv(struct state *st, const msgid_t *msgid)
{
	const struct hash_desc *h = st->st_oakley.hasher;
	union hash_ctx ctx;

	DBG_cond_dump(DBG_CRYPT, "last Phase 1 IV:"
		, st->st_ph1_iv, st->st_ph1_iv_len);

	st->st_new_iv_len = h->hash_digest_size;
	passert(st->st_new_iv_len <= sizeof(st->st_new_iv));

	h->hash_init(&ctx);
	h->hash_update(&ctx, st->st_ph1_iv, st->st_ph1_iv_len);
	passert(*msgid != 0);
	h->hash_update(&ctx, (const u_char *)msgid, sizeof(*msgid));
	h->hash_final(st->st_new_iv, &ctx);

	DBG_cond_dump(DBG_CRYPT, "computed Phase 2 IV:"
		, st->st_new_iv, st->st_new_iv_len);
}

/* Initiate quick mode.
 * --> HDR*, HASH(1), SA, Nr [, KE ] [, IDci, IDcr ]
 * (see RFC 2409 "IKE" 5.5)
 * Note: this is not called from demux.c
 */

static bool emit_subnet_id(ip_subnet *net, u_int8_t np, u_int8_t protoid,
						   u_int16_t port, pb_stream *outs)
{
	struct isakmp_ipsec_id id;
	pb_stream id_pbs;
	ip_address ta;
	const unsigned char *tbp;
	size_t tal;

	id.isaiid_np = np;
	id.isaiid_idtype = subnetishost(net)
					   ? aftoinfo(subnettypeof(net))->id_addr
					   : aftoinfo(subnettypeof(net))->id_subnet;
	id.isaiid_protoid = protoid;
	id.isaiid_port = port;

	if (!out_struct(&id, &isakmp_ipsec_identification_desc, outs, &id_pbs))
		return FALSE;

	networkof(net, &ta);
	tal = addrbytesptr(&ta, &tbp);
	if (!out_raw(tbp, tal, &id_pbs, "client network"))
		return FALSE;

	if (!subnetishost(net))
	{
		maskof(net, &ta);
		tal = addrbytesptr(&ta, &tbp);
		if (!out_raw(tbp, tal, &id_pbs, "client mask"))
			return FALSE;
	}

	close_output_pbs(&id_pbs);
	return TRUE;
}

stf_status quick_outI1(int whack_sock, struct state *isakmp_sa,
					   struct connection *c, lset_t policy, unsigned long try,
					   so_serial_t replacing)
{
	struct state *st = duplicate_state(isakmp_sa);
	pb_stream reply;    /* not really a reply */
	pb_stream rbody;
	u_char      /* set by START_HASH_PAYLOAD: */
		*r_hashval,     /* where in reply to jam hash value */
		*r_hash_start;  /* start of what is to be hashed */
	bool has_client = c->spd.this.has_client || c->spd.that.has_client ||
					  c->spd.this.protocol || c->spd.that.protocol ||
					  c->spd.this.port || c->spd.that.port;
	
	bool send_natoa = FALSE;
	u_int8_t np = ISAKMP_NEXT_NONE;

	st->st_whack_sock = whack_sock;
	st->st_connection = c;
	set_cur_state(st);  /* we must reset before exit */
	st->st_policy = policy;
	st->st_try = try;

	st->st_myuserprotoid = c->spd.this.protocol;
	st->st_peeruserprotoid = c->spd.that.protocol;
	st->st_myuserport = c->spd.this.port;
	st->st_peeruserport = c->spd.that.port;

	st->st_msgid = generate_msgid(isakmp_sa);
	st->st_state = STATE_QUICK_I1;

	insert_state(st);   /* needs cookies, connection, and msgid */

	if (replacing == SOS_NOBODY)
		plog("initiating Quick Mode %s {using isakmp#%lu}"
			 , prettypolicy(policy)
			 , isakmp_sa->st_serialno);
	else
		plog("initiating Quick Mode %s to replace #%lu {using isakmp#%lu}"
			 , prettypolicy(policy)
			 , replacing
			 , isakmp_sa->st_serialno);

	if (isakmp_sa->nat_traversal & NAT_T_DETECTED)
	{
		/* Duplicate nat_traversal status in new state */
		st->nat_traversal = isakmp_sa->nat_traversal;

		if (isakmp_sa->nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_ME))
			has_client = TRUE;

	   nat_traversal_change_port_lookup(NULL, st);
	}
	else
		st->nat_traversal = 0;

	/* are we going to send a NAT-OA payload? */
	if ((st->nat_traversal & NAT_T_WITH_NATOA)
	&& !(st->st_policy & POLICY_TUNNEL)
	&& (st->nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_ME)))
	{
		send_natoa = TRUE;
		np = (st->nat_traversal & NAT_T_WITH_RFC_VALUES) ?
				  ISAKMP_NEXT_NATOA_RFC : ISAKMP_NEXT_NATOA_DRAFTS;
	}

	/* set up reply */
	init_pbs(&reply, reply_buffer, sizeof(reply_buffer), "reply packet");

	/* HDR* out */
	{
		struct isakmp_hdr hdr;

		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_QUICK;
		hdr.isa_msgid = st->st_msgid;
		hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
		{
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* HASH(1) -- create and note space to be filled later */
	START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_SA);

	/* SA out */

	/* 
	 * See if pfs_group has been specified for this conn,
	 * if not, fallback to old use-same-as-P1 behaviour
	 */
#ifndef NO_IKE_ALG
	if (st->st_connection)
			st->st_pfs_group = ike_alg_pfsgroup(st->st_connection, policy);
	if (!st->st_pfs_group)
#endif
	/* If PFS specified, use the same group as during Phase 1:
	 * since no negotiation is possible, we pick one that is
	 * very likely supported.
	 */
			st->st_pfs_group = policy & POLICY_PFS? isakmp_sa->st_oakley.group : NULL;

	/* Emit SA payload based on a subset of the policy bits.
	 * POLICY_COMPRESS is considered iff we can do IPcomp.
	 */
	{
		lset_t pm = POLICY_ENCRYPT | POLICY_AUTHENTICATE;

		if (can_do_IPcomp)
			pm |= POLICY_COMPRESS;

		if (!out_sa(&rbody
		, &ipsec_sadb[(st->st_policy & pm) >> POLICY_IPSEC_SHIFT]
		, st, FALSE, ISAKMP_NEXT_NONCE))
		{
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* Ni out */
	if (!build_and_ship_nonce(&st->st_ni, &rbody
	, policy & POLICY_PFS? ISAKMP_NEXT_KE : has_client? ISAKMP_NEXT_ID : np
	, "Ni"))
	{
		reset_cur_state();
		return STF_INTERNAL_ERROR;
	}

	/* [ KE ] out (for PFS) */

	if (st->st_pfs_group != NULL)
	{
		if (!build_and_ship_KE(st, &st->st_gi, st->st_pfs_group
		, &rbody, has_client? ISAKMP_NEXT_ID : np))
		{
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* [ IDci, IDcr ] out */
	if (has_client)
	{
		/* IDci (we are initiator), then IDcr (peer is responder) */
		if (!emit_subnet_id(&c->spd.this.client
		  , ISAKMP_NEXT_ID, st->st_myuserprotoid, st->st_myuserport, &rbody)
		|| !emit_subnet_id(&c->spd.that.client
		  , np, st->st_peeruserprotoid, st->st_peeruserport, &rbody))
		{
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* Send NAT-OA if our address is NATed */
	if (send_natoa)
	{
		if (!nat_traversal_add_natoa(ISAKMP_NEXT_NONE, &rbody, st))
		{
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* finish computing  HASH(1), inserting it in output */
	(void) quick_mode_hash12(r_hashval, r_hash_start, rbody.cur
		, st, &st->st_msgid, FALSE);

	/* encrypt message, except for fixed part of header */

	init_phase2_iv(isakmp_sa, &st->st_msgid);
	st->st_new_iv_len = isakmp_sa->st_new_iv_len;
	memcpy(st->st_new_iv, isakmp_sa->st_new_iv, st->st_new_iv_len);

	if (!encrypt_message(&rbody, st))
	{
		reset_cur_state();
		return STF_INTERNAL_ERROR;
	}

	/* save packet, now that we know its size */
	st->st_tpacket = chunk_create(reply.start, pbs_offset(&reply));
	st->st_tpacket = chunk_clone(st->st_tpacket);

	/* send the packet */

	send_packet(st, "quick_outI1");

	delete_event(st);
	event_schedule(EVENT_RETRANSMIT, EVENT_RETRANSMIT_DELAY_0, st);

	if (replacing == SOS_NOBODY)
		whack_log(RC_NEW_STATE + STATE_QUICK_I1
			, "%s: initiate"
			, enum_name(&state_names, st->st_state));
	else
		whack_log(RC_NEW_STATE + STATE_QUICK_I1
			, "%s: initiate to replace #%lu"
			, enum_name(&state_names, st->st_state)
			, replacing);
	reset_cur_state();
	return STF_OK;
}


/*
 * Decode the CERT payload of Phase 1.
 */
static void decode_cert(struct msg_digest *md)
{
	struct payload_digest *p;

	for (p = md->chain[ISAKMP_NEXT_CERT]; p != NULL; p = p->next)
	{
		struct isakmp_cert *const cert = &p->payload.cert;
		chunk_t blob;
		time_t valid_until;
		blob.ptr = p->pbs.cur;
		blob.len = pbs_left(&p->pbs);
		if (cert->isacert_type == CERT_X509_SIGNATURE)
		{
			x509cert_t cert = empty_x509cert;
			if (parse_x509cert(blob, 0, &cert))
			{
				if (verify_x509cert(&cert, strict_crl_policy, &valid_until))
				{
					DBG(DBG_PARSING,
						DBG_log("Public key validated")
					)
					add_x509_public_key(&cert, valid_until, DAL_SIGNED);
				}
				else
				{
					plog("X.509 certificate rejected");
				}
				free_generalNames(cert.subjectAltName, FALSE);
				free_generalNames(cert.crlDistributionPoints, FALSE);
			}
			else
				plog("Syntax error in X.509 certificate");
		}
		else if (cert->isacert_type == CERT_PKCS7_WRAPPED_X509)
		{
			x509cert_t *cert = NULL;

			if (pkcs7_parse_signedData(blob, NULL, &cert, NULL, NULL))
				store_x509certs(&cert, strict_crl_policy);
			else
				plog("Syntax error in PKCS#7 wrapped X.509 certificates");
		}
		else
		{
			loglog(RC_LOG_SERIOUS, "ignoring %s certificate payload",
				   enum_show(&cert_type_names, cert->isacert_type));
			DBG_cond_dump_chunk(DBG_PARSING, "CERT:\n", blob);
		}
	}
}

/*
 * Decode the CR payload of Phase 1.
 */
static void decode_cr(struct msg_digest *md, struct connection *c)
{
	struct payload_digest *p;

	for (p = md->chain[ISAKMP_NEXT_CR]; p != NULL; p = p->next)
	{
		struct isakmp_cr *const cr = &p->payload.cr;
		chunk_t ca_name;
		
		ca_name.len = pbs_left(&p->pbs);
		ca_name.ptr = (ca_name.len > 0)? p->pbs.cur : NULL;

		DBG_cond_dump_chunk(DBG_PARSING, "CR", ca_name);

		if (cr->isacr_type == CERT_X509_SIGNATURE)
		{
			char buf[BUF_LEN];

			if (ca_name.len > 0)
			{
				generalName_t *gn;
				
				if (!is_asn1(ca_name))
					continue;

				gn = malloc_thing(generalName_t);
				ca_name = chunk_clone(ca_name);
				gn->kind = GN_DIRECTORY_NAME;
				gn->name = ca_name;
				gn->next = c->requested_ca;
				c->requested_ca = gn;
			}
			c->got_certrequest = TRUE;

			DBG(DBG_PARSING | DBG_CONTROL,
				dntoa_or_null(buf, BUF_LEN, ca_name, "%any");
				DBG_log("requested CA: '%s'", buf);
			)
		}
		else
			loglog(RC_LOG_SERIOUS, "ignoring %s certificate request payload",
				   enum_show(&cert_type_names, cr->isacr_type));
	}
}

/* Decode the ID payload of Phase 1 (main_inI3_outR3 and main_inR3)
 * Note: we may change connections as a result.
 * We must be called before SIG or HASH are decoded since we
 * may change the peer's RSA key or ID.
 */
static bool decode_peer_id(struct msg_digest *md, struct id *peer)
{
	struct state *const st = md->st;
	struct payload_digest *const id_pld = md->chain[ISAKMP_NEXT_ID];
	const pb_stream *const id_pbs = &id_pld->pbs;
	struct isakmp_id *const id = &id_pld->payload.id;

	/* I think that RFC2407 (IPSEC DOI) 4.6.2 is confused.
	 * It talks about the protocol ID and Port fields of the ID
	 * Payload, but they don't exist as such in Phase 1.
	 * We use more appropriate names.
	 * isaid_doi_specific_a is in place of Protocol ID.
	 * isaid_doi_specific_b is in place of Port.
	 * Besides, there is no good reason for allowing these to be
	 * other than 0 in Phase 1.
	 */
	if ((st->nat_traversal & NAT_T_WITH_PORT_FLOATING)
	&&   id->isaid_doi_specific_a == IPPROTO_UDP
	&&  (id->isaid_doi_specific_b == 0 || id->isaid_doi_specific_b == NAT_T_IKE_FLOAT_PORT))
	{
		DBG_log("protocol/port in Phase 1 ID Payload is %d/%d. "
				"accepted with port_floating NAT-T",
				id->isaid_doi_specific_a, id->isaid_doi_specific_b);
	}
	else if (!(id->isaid_doi_specific_a == 0 && id->isaid_doi_specific_b == 0)
		 &&  !(id->isaid_doi_specific_a == IPPROTO_UDP && id->isaid_doi_specific_b == IKE_UDP_PORT))
	{
		loglog(RC_LOG_SERIOUS, "protocol/port in Phase 1 ID Payload must be 0/0 or %d/%d"
			" but are %d/%d"
			, IPPROTO_UDP, IKE_UDP_PORT
			, id->isaid_doi_specific_a, id->isaid_doi_specific_b);
		return FALSE;
	}

	peer->kind = id->isaid_idtype;

	switch (peer->kind)
	{
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		/* failure mode for initaddr is probably inappropriate address length */
		{
			err_t ugh = initaddr(id_pbs->cur, pbs_left(id_pbs)
				, peer->kind == ID_IPV4_ADDR? AF_INET : AF_INET6
				, &peer->ip_addr);

			if (ugh != NULL)
			{
				loglog(RC_LOG_SERIOUS, "improper %s identification payload: %s"
					, enum_show(&ident_names, peer->kind), ugh);
				/* XXX Could send notification back */
				return FALSE;
			}
		}
		break;

	case ID_USER_FQDN:
		if (memchr(id_pbs->cur, '@', pbs_left(id_pbs)) == NULL)
		{
			loglog(RC_LOG_SERIOUS, "peer's ID_USER_FQDN contains no @");
			return FALSE;
		}
		/* FALLTHROUGH */
	case ID_FQDN:
		if (memchr(id_pbs->cur, '\0', pbs_left(id_pbs)) != NULL)
		{
			loglog(RC_LOG_SERIOUS, "Phase 1 ID Payload of type %s contains a NUL"
				, enum_show(&ident_names, peer->kind));
			return FALSE;
		}

		/* ??? ought to do some more sanity check, but what? */

		peer->name = chunk_create(id_pbs->cur, pbs_left(id_pbs));
		break;

	case ID_KEY_ID:
		peer->name = chunk_create(id_pbs->cur, pbs_left(id_pbs));
		DBG(DBG_PARSING,
			DBG_dump_chunk("KEY ID:", peer->name));
		break;

	case ID_DER_ASN1_DN:
		peer->name = chunk_create(id_pbs->cur, pbs_left(id_pbs));
		DBG(DBG_PARSING,
			DBG_dump_chunk("DER ASN1 DN:", peer->name));
		break;

	default:
		/* XXX Could send notification back */
		loglog(RC_LOG_SERIOUS, "Unacceptable identity type (%s) in Phase 1 ID Payload"
			, enum_show(&ident_names, peer->kind));
		return FALSE;
	}

	{
		char buf[BUF_LEN];

		idtoa(peer, buf, sizeof(buf));
		plog("Peer ID is %s: '%s'",
			enum_show(&ident_names, id->isaid_idtype), buf);
	}

	/* check for certificates */
	decode_cert(md);
	return TRUE;
}

/* Now that we've decoded the ID payload, let's see if we
 * need to switch connections.
 * We must not switch horses if we initiated:
 * - if the initiation was explicit, we'd be ignoring user's intent
 * - if opportunistic, we'll lose our HOLD info
 */
static bool switch_connection(struct msg_digest *md, struct id *peer,
							  bool initiator)
{
	struct state *const st = md->st;
	struct connection *c = st->st_connection;

	chunk_t peer_ca = (st->st_peer_pubkey != NULL)
					 ? st->st_peer_pubkey->issuer : chunk_empty;

	DBG(DBG_CONTROL,
		char buf[BUF_LEN];

		dntoa_or_null(buf, BUF_LEN, peer_ca, "%none");
		DBG_log("peer CA:      '%s'", buf);
	)

	if (initiator)
	{
		int pathlen;

		if (!same_id(&c->spd.that.id, peer))
		{
			char expect[BUF_LEN]
				, found[BUF_LEN];

			idtoa(&c->spd.that.id, expect, sizeof(expect));
			idtoa(peer, found, sizeof(found));
			loglog(RC_LOG_SERIOUS
				, "we require peer to have ID '%s', but peer declares '%s'"
				, expect, found);
			return FALSE;
		}

		DBG(DBG_CONTROL,
			char buf[BUF_LEN];

			dntoa_or_null(buf, BUF_LEN, c->spd.that.ca, "%none");
			DBG_log("required CA:  '%s'", buf);
		)

		if (!trusted_ca(peer_ca, c->spd.that.ca, &pathlen))
		{
			loglog(RC_LOG_SERIOUS
				, "we don't accept the peer's CA");
			return FALSE;
		}
	}
	else
	{
		struct connection *r;

		/* check for certificate requests */
		decode_cr(md, c);

		r = refine_host_connection(st, peer, peer_ca);

		/* delete the collected certificate requests */
		free_generalNames(c->requested_ca, TRUE);
		c->requested_ca = NULL;

		if (r == NULL)
		{
			char buf[BUF_LEN];

			idtoa(peer, buf, sizeof(buf));
			loglog(RC_LOG_SERIOUS, "no suitable connection for peer '%s'", buf);
			return FALSE;
		}

		DBG(DBG_CONTROL,
			char buf[BUF_LEN];

			dntoa_or_null(buf, BUF_LEN, r->spd.this.ca, "%none");
			DBG_log("offered CA:   '%s'", buf);
		)

		if (r != c)
		{
			/* apparently, r is an improvement on c -- replace */

			DBG(DBG_CONTROL
				, DBG_log("switched from \"%s\" to \"%s\"", c->name, r->name));
			if (r->kind == CK_TEMPLATE)
			{
				/* instantiate it, filling in peer's ID */
				r = rw_instantiate(r, &c->spd.that.host_addr
						, c->spd.that.host_port, NULL, peer);
			}

			/* copy certificate request info */
			r->got_certrequest = c->got_certrequest;

			st->st_connection = r;      /* kill reference to c */
			set_cur_connection(r);
			connection_discard(c);
		}
		else if (c->spd.that.has_id_wildcards)
		{
			free_id_content(&c->spd.that.id);
			c->spd.that.id = *peer;
			c->spd.that.has_id_wildcards = FALSE;
			unshare_id_content(&c->spd.that.id);
		}
	}
	return TRUE;
}

/* Decode the variable part of an ID packet (during Quick Mode).
 * This is designed for packets that identify clients, not peers.
 * Rejects 0.0.0.0/32 or IPv6 equivalent because
 * (1) it is wrong and (2) we use this value for inband signalling.
 */
static bool decode_net_id(struct isakmp_ipsec_id *id, pb_stream *id_pbs,
						  ip_subnet *net, const char *which)
{
	const struct af_info *afi = NULL;

	/* Note: the following may be a pointer into static memory
	 * that may be recycled, but only if the type is not known.
	 * That case is disposed of very early -- in the first switch.
	 */
	const char *idtypename = enum_show(&ident_names, id->isaiid_idtype);

	switch (id->isaiid_idtype)
	{
		case ID_IPV4_ADDR:
		case ID_IPV4_ADDR_SUBNET:
		case ID_IPV4_ADDR_RANGE:
			afi = &af_inet4_info;
			break;
		case ID_IPV6_ADDR:
		case ID_IPV6_ADDR_SUBNET:
		case ID_IPV6_ADDR_RANGE:
			afi = &af_inet6_info;
			break;
		case ID_FQDN:
			return TRUE;
		default:
			/* XXX support more */
			loglog(RC_LOG_SERIOUS, "unsupported ID type %s"
				, idtypename);
			/* XXX Could send notification back */
			return FALSE;
	}

	switch (id->isaiid_idtype)
	{
		case ID_IPV4_ADDR:
		case ID_IPV6_ADDR:
		{
			ip_address temp_address;
			err_t ugh;

			ugh = initaddr(id_pbs->cur, pbs_left(id_pbs), afi->af, &temp_address);

			if (ugh != NULL)
			{
				loglog(RC_LOG_SERIOUS, "%s ID payload %s has wrong length in Quick I1 (%s)"
					, which, idtypename, ugh);
				/* XXX Could send notification back */
				return FALSE;
			}
			if (isanyaddr(&temp_address))
			{
				loglog(RC_LOG_SERIOUS, "%s ID payload %s is invalid (%s) in Quick I1"
					, which, idtypename, ip_str(&temp_address));
				/* XXX Could send notification back */
				return FALSE;
			}
			happy(addrtosubnet(&temp_address, net));
			DBG(DBG_PARSING | DBG_CONTROL
				, DBG_log("%s is %s", which, ip_str(&temp_address)));
			break;
		}

		case ID_IPV4_ADDR_SUBNET:
		case ID_IPV6_ADDR_SUBNET:
		{
			ip_address temp_address, temp_mask;
			err_t ugh;

			if (pbs_left(id_pbs) != 2 * afi->ia_sz)
			{
				loglog(RC_LOG_SERIOUS, "%s ID payload %s wrong length in Quick I1"
					, which, idtypename);
				/* XXX Could send notification back */
				return FALSE;
			}
			ugh = initaddr(id_pbs->cur
				, afi->ia_sz, afi->af, &temp_address);
			if (ugh == NULL)
				ugh = initaddr(id_pbs->cur + afi->ia_sz
					, afi->ia_sz, afi->af, &temp_mask);
			if (ugh == NULL)
				ugh = initsubnet(&temp_address, masktocount(&temp_mask)
					, '0', net);
			if (ugh == NULL && subnetisnone(net))
				ugh = "contains only anyaddr";
			if (ugh != NULL)
			{
				loglog(RC_LOG_SERIOUS, "%s ID payload %s bad subnet in Quick I1 (%s)"
					, which, idtypename, ugh);
				/* XXX Could send notification back */
				return FALSE;
			}
			DBG(DBG_PARSING | DBG_CONTROL,
				{
					char temp_buff[SUBNETTOT_BUF];

					subnettot(net, 0, temp_buff, sizeof(temp_buff));
					DBG_log("%s is subnet %s", which, temp_buff);
				});
			break;
		}

		case ID_IPV4_ADDR_RANGE:
		case ID_IPV6_ADDR_RANGE:
		{
			ip_address temp_address_from, temp_address_to;
			err_t ugh;

			if (pbs_left(id_pbs) != 2 * afi->ia_sz)
			{
				loglog(RC_LOG_SERIOUS, "%s ID payload %s wrong length in Quick I1"
					, which, idtypename);
				/* XXX Could send notification back */
				return FALSE;
			}
			ugh = initaddr(id_pbs->cur, afi->ia_sz, afi->af, &temp_address_from);
			if (ugh == NULL)
				ugh = initaddr(id_pbs->cur + afi->ia_sz
					, afi->ia_sz, afi->af, &temp_address_to);
			if (ugh != NULL)
			{
				loglog(RC_LOG_SERIOUS, "%s ID payload %s malformed (%s) in Quick I1"
					, which, idtypename, ugh);
				/* XXX Could send notification back */
				return FALSE;
			}

			ugh = rangetosubnet(&temp_address_from, &temp_address_to, net);
			if (ugh == NULL && subnetisnone(net))
				ugh = "contains only anyaddr";
			if (ugh != NULL)
			{
				char temp_buff1[ADDRTOT_BUF], temp_buff2[ADDRTOT_BUF];

				addrtot(&temp_address_from, 0, temp_buff1, sizeof(temp_buff1));
				addrtot(&temp_address_to, 0, temp_buff2, sizeof(temp_buff2));
				loglog(RC_LOG_SERIOUS, "%s ID payload in Quick I1, %s"
					" %s - %s unacceptable: %s"
					, which, idtypename, temp_buff1, temp_buff2, ugh);
				return FALSE;
			}
			DBG(DBG_PARSING | DBG_CONTROL,
				{
					char temp_buff[SUBNETTOT_BUF];

					subnettot(net, 0, temp_buff, sizeof(temp_buff));
					DBG_log("%s is subnet %s (received as range)"
						, which, temp_buff);
				});
			break;
		}
	}

	/* set the port selector */
	setportof(htons(id->isaiid_port), &net->addr);

	DBG(DBG_PARSING | DBG_CONTROL,
		DBG_log("%s protocol/port is %d/%d", which, id->isaiid_protoid, id->isaiid_port)
	)

	return TRUE;
}

/* like decode, but checks that what is received matches what was sent */
static bool check_net_id(struct isakmp_ipsec_id *id, pb_stream *id_pbs,
						 u_int8_t *protoid, u_int16_t *port, ip_subnet *net,
						 const char *which)
{
	ip_subnet net_temp;

	if (!decode_net_id(id, id_pbs, &net_temp, which))
		return FALSE;

	if (!samesubnet(net, &net_temp)
	|| *protoid != id->isaiid_protoid || *port != id->isaiid_port)
	{
		loglog(RC_LOG_SERIOUS, "%s ID returned doesn't match my proposal", which);
		return FALSE;
	}
	return TRUE;
}

/*
 * look for the existence of a non-expiring preloaded public key
 */
static bool has_preloaded_public_key(struct state *st)
{
	struct connection *c = st->st_connection;

	/* do not consider rw connections since
	 * the peer's identity must be known
	 */
	if (c->kind == CK_PERMANENT)
	{
		pubkey_list_t *p;

		/* look for a matching RSA public key */
		for (p = pubkeys; p != NULL; p = p->next)
		{
			pubkey_t *key = p->key;

			if (key->alg == PUBKEY_ALG_RSA &&
				same_id(&c->spd.that.id, &key->id) &&
				key->until_time == UNDEFINED_TIME)
			{
				/* found a preloaded public key */
				return TRUE;
			}
		}
	}
	return FALSE;
}

/*
 * Produce the new key material of Quick Mode.
 * RFC 2409 "IKE" section 5.5
 * specifies how this is to be done.
 */
static void compute_proto_keymat(struct state *st, u_int8_t protoid,
								 struct ipsec_proto_info *pi)
{
	size_t needed_len = 0; /* bytes of keying material needed */

	/* Add up the requirements for keying material
	 * (It probably doesn't matter if we produce too much!)
	 */
	switch (protoid)
	{
	case PROTO_IPSEC_ESP:
			switch (pi->attrs.transid)
			{
			case ESP_NULL:
				needed_len = 0;
				break;
			case ESP_DES:
				needed_len = DES_CBC_BLOCK_SIZE;
				break;
			case ESP_3DES:
				needed_len = DES_CBC_BLOCK_SIZE * 3;
				break;
			default:
#ifndef NO_KERNEL_ALG
				if((needed_len=kernel_alg_esp_enc_keylen(pi->attrs.transid))>0) {
						/* XXX: check key_len "coupling with kernel.c's */
						if (pi->attrs.key_len) {
								needed_len=pi->attrs.key_len/8;
								DBG(DBG_PARSING, DBG_log("compute_proto_keymat:"
												"key_len=%d from peer",
												(int)needed_len));
						}
						break;
				}
#endif
				bad_case(pi->attrs.transid);
			}

#ifndef NO_KERNEL_ALG
			DBG(DBG_PARSING, DBG_log("compute_proto_keymat:"
									"needed_len (after ESP enc)=%d",
									(int)needed_len));
			if (kernel_alg_esp_auth_ok(pi->attrs.auth, NULL)) {
				needed_len += kernel_alg_esp_auth_keylen(pi->attrs.auth);
			} else
#endif
			switch (pi->attrs.auth)
			{
			case AUTH_ALGORITHM_NONE:
				break;
			case AUTH_ALGORITHM_HMAC_MD5:
				needed_len += HMAC_MD5_KEY_LEN;
				break;
			case AUTH_ALGORITHM_HMAC_SHA1:
				needed_len += HMAC_SHA1_KEY_LEN;
				break;
			case AUTH_ALGORITHM_DES_MAC:
			default:
				bad_case(pi->attrs.auth);
			}
			DBG(DBG_PARSING, DBG_log("compute_proto_keymat:"
									"needed_len (after ESP auth)=%d",
									(int)needed_len));
			break;

	case PROTO_IPSEC_AH:
			switch (pi->attrs.transid)
			{
			case AH_MD5:
				needed_len = HMAC_MD5_KEY_LEN;
				break;
			case AH_SHA:
				needed_len = HMAC_SHA1_KEY_LEN;
				break;
			default:
				bad_case(pi->attrs.transid);
			}
			break;

	default:
		bad_case(protoid);
	}

	pi->keymat_len = needed_len;

	/* Allocate space for the keying material.
	 * Although only needed_len bytes are desired, we
	 * must round up to a multiple of ctx.hmac_digest_size
	 * so that our buffer isn't overrun.
	 */
	{
		struct hmac_ctx ctx_me, ctx_peer;
		size_t needed_space;    /* space needed for keying material (rounded up) */
		size_t i;

		hmac_init_chunk(&ctx_me, st->st_oakley.hasher, st->st_skeyid_d);
		ctx_peer = ctx_me;      /* duplicate initial conditions */

		needed_space = needed_len + pad_up(needed_len, ctx_me.hmac_digest_size);
		replace(pi->our_keymat, malloc(needed_space));
		replace(pi->peer_keymat, malloc(needed_space));

		for (i = 0;; )
		{
			if (st->st_shared.ptr != NULL)
			{
				/* PFS: include the g^xy */
				hmac_update_chunk(&ctx_me, st->st_shared);
				hmac_update_chunk(&ctx_peer, st->st_shared);
			}
			hmac_update(&ctx_me, &protoid, sizeof(protoid));
			hmac_update(&ctx_peer, &protoid, sizeof(protoid));

			hmac_update(&ctx_me, (u_char *)&pi->our_spi, sizeof(pi->our_spi));
			hmac_update(&ctx_peer, (u_char *)&pi->attrs.spi, sizeof(pi->attrs.spi));

			hmac_update_chunk(&ctx_me, st->st_ni);
			hmac_update_chunk(&ctx_peer, st->st_ni);

			hmac_update_chunk(&ctx_me, st->st_nr);
			hmac_update_chunk(&ctx_peer, st->st_nr);

			hmac_final(pi->our_keymat + i, &ctx_me);
			hmac_final(pi->peer_keymat + i, &ctx_peer);

			i += ctx_me.hmac_digest_size;
			if (i >= needed_space)
				break;

			/* more keying material needed: prepare to go around again */

			hmac_reinit(&ctx_me);
			hmac_reinit(&ctx_peer);

			hmac_update(&ctx_me, pi->our_keymat + i - ctx_me.hmac_digest_size
				, ctx_me.hmac_digest_size);
			hmac_update(&ctx_peer, pi->peer_keymat + i - ctx_peer.hmac_digest_size
				, ctx_peer.hmac_digest_size);
		}
	}

	DBG(DBG_CRYPT,
		DBG_dump("KEYMAT computed:\n", pi->our_keymat, pi->keymat_len);
		DBG_dump("Peer KEYMAT computed:\n", pi->peer_keymat, pi->keymat_len));
}

static void compute_keymats(struct state *st)
{
	if (st->st_ah.present)
		compute_proto_keymat(st, PROTO_IPSEC_AH, &st->st_ah);
	if (st->st_esp.present)
		compute_proto_keymat(st, PROTO_IPSEC_ESP, &st->st_esp);
}

/* State Transition Functions.
 *
 * The definition of state_microcode_table in demux.c is a good
 * overview of these routines.
 *
 * - Called from process_packet; result handled by complete_state_transition
 * - struct state_microcode member "processor" points to these
 * - these routine definitionss are in state order
 * - these routines must be restartable from any point of error return:
 *   beware of memory allocated before any error.
 * - output HDR is usually emitted by process_packet (if state_microcode
 *   member first_out_payload isn't ISAKMP_NEXT_NONE).
 *
 * The transition functions' functions include:
 * - process and judge payloads
 * - update st_iv (result of decryption is in st_new_iv)
 * - build reply packet
 */

/* Handle a Main Mode Oakley first packet (responder side).
 * HDR;SA --> HDR;SA
 */
stf_status
main_inI1_outR1(struct msg_digest *md)
{
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];
	struct state *st;
	struct connection *c;
	struct isakmp_proposal proposal;
	pb_stream proposal_pbs;
	pb_stream r_sa_pbs;
	u_int32_t ipsecdoisit;
	lset_t policy = LEMPTY;
	int vids_to_send = 0;

	/* We preparse the peer's proposal in order to determine
	 * the requested authentication policy (RSA or PSK)
	 */
	RETURN_STF_FAILURE(preparse_isakmp_sa_body(&sa_pd->payload.sa
		, &sa_pd->pbs, &ipsecdoisit, &proposal_pbs, &proposal));

	backup_pbs(&proposal_pbs);
	RETURN_STF_FAILURE(parse_isakmp_policy(&proposal_pbs
					 , proposal.isap_notrans, &policy));
	restore_pbs(&proposal_pbs);

	/* We are only considering candidate connections that match
	 * the requested authentication policy (RSA or PSK)
	 */
	c = find_host_connection(&md->iface->addr, pluto_port
						   , &md->sender, md->sender_port, policy);

	if (c == NULL && md->iface->ike_float)
	{
		c = find_host_connection(&md->iface->addr, NAT_T_IKE_FLOAT_PORT
				, &md->sender, md->sender_port, policy);
	}

	if (c == NULL)
	{
		/* See if a wildcarded connection can be found.
		 * We cannot pick the right connection, so we're making a guess.
		 * All Road Warrior connections are fair game:
		 * we pick the first we come across (if any).
		 * If we don't find any, we pick the first opportunistic
		 * with the smallest subnet that includes the peer.
		 * There is, of course, no necessary relationship between
		 * an Initiator's address and that of its client,
		 * but Food Groups kind of assumes one.
		 */
		{
			struct connection *d;

			d = find_host_connection(&md->iface->addr
				, pluto_port, (ip_address*)NULL, md->sender_port, policy);

			for (; d != NULL; d = d->hp_next)
			{
				if (d->kind == CK_GROUP)
				{
					/* ignore */
				}
				else
				{
					if (d->kind == CK_TEMPLATE && !(d->policy & POLICY_OPPO))
					{
						/* must be Road Warrior: we have a winner */
						c = d;
						break;
					}

					/* Opportunistic or Shunt: pick tightest match */
					if (addrinsubnet(&md->sender, &d->spd.that.client)
					&& (c == NULL || !subnetinsubnet(&c->spd.that.client, &d->spd.that.client)))
						c = d;
				}
			}
		}

		if (c == NULL)
		{
			loglog(RC_LOG_SERIOUS, "initial Main Mode message received on %s:%u"
				" but no connection has been authorized%s%s"
				, ip_str(&md->iface->addr), ntohs(portof(&md->iface->addr))
				, (policy != LEMPTY) ? " with policy=" : ""
				, (policy != LEMPTY) ? bitnamesof(sa_policy_bit_names, policy) : "");
			/* XXX notification is in order! */
			return STF_IGNORE;
		}
		else if (c->kind != CK_TEMPLATE)
		{
			loglog(RC_LOG_SERIOUS, "initial Main Mode message received on %s:%u"
				" but \"%s\" forbids connection"
				, ip_str(&md->iface->addr), pluto_port, c->name);
			/* XXX notification is in order! */
			return STF_IGNORE;
		}
		else
		{
			/* Create a temporary connection that is a copy of this one.
			 * His ID isn't declared yet.
			 */
			c = rw_instantiate(c, &md->sender, md->sender_port, NULL, NULL);
		}
	}
	else if (c->kind == CK_TEMPLATE)
	{
		/* Create an instance
		 * This is a rare case: wildcard peer ID but static peer IP address
		 */
		 c = rw_instantiate(c, &md->sender, md->sender_port, NULL, &c->spd.that.id);
	}

	/* Set up state */
	md->st = st = new_state();
	st->st_connection = c;
	set_cur_state(st);  /* (caller will reset cur_state) */
	st->st_try = 0;     /* not our job to try again from start */
	st->st_policy = c->policy & ~POLICY_IPSEC_MASK;     /* only as accurate as connection */

	memcpy(st->st_icookie, md->hdr.isa_icookie, COOKIE_SIZE);
	get_cookie(FALSE, st->st_rcookie, COOKIE_SIZE, &md->sender);

	insert_state(st);   /* needs cookies, connection, and msgid (0) */

	st->st_doi = ISAKMP_DOI_IPSEC;
	st->st_situation = SIT_IDENTITY_ONLY; /* We only support this */

	if ((c->kind == CK_INSTANCE) && (c->spd.that.host_port != pluto_port))
	{
	   plog("responding to Main Mode from unknown peer %s:%u"
			, ip_str(&c->spd.that.host_addr), c->spd.that.host_port);
	}
	else if (c->kind == CK_INSTANCE)
	{
		plog("responding to Main Mode from unknown peer %s"
			, ip_str(&c->spd.that.host_addr));
	}
	else
	{
		plog("responding to Main Mode");
	}

	/* parse_isakmp_sa also spits out a winning SA into our reply,
	 * so we have to build our md->reply and emit HDR before calling it.
	 */

	/* determine how many Vendor ID payloads we will be sending */
	if (SEND_PLUTO_VID)
		vids_to_send++;
	if (SEND_CISCO_UNITY_VID)
		vids_to_send++;
	if (md->openpgp)
		vids_to_send++;
	if (SEND_XAUTH_VID)
		vids_to_send++;
	/* always send DPD Vendor ID */
		vids_to_send++;
	if (md->nat_traversal_vid && nat_traversal_enabled)
		vids_to_send++;

	/* HDR out.
	 * We can't leave this to comm_handle() because we must
	 * fill in the cookie.
	 */
	{
		struct isakmp_hdr r_hdr = md->hdr;

		r_hdr.isa_flags &= ~ISAKMP_FLAG_COMMIT; /* we won't ever turn on this bit */
		memcpy(r_hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		r_hdr.isa_np = ISAKMP_NEXT_SA;
		if (!out_struct(&r_hdr, &isakmp_hdr_desc, &md->reply, &md->rbody))
			return STF_INTERNAL_ERROR;
	}

	/* start of SA out */
	{
		struct isakmp_sa r_sa = sa_pd->payload.sa;

		r_sa.isasa_np = vids_to_send-- ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE;

		if (!out_struct(&r_sa, &isakmp_sa_desc, &md->rbody, &r_sa_pbs))
			return STF_INTERNAL_ERROR;
	}

	/* SA body in and out */
	RETURN_STF_FAILURE(parse_isakmp_sa_body(ipsecdoisit, &proposal_pbs
		,&proposal, &r_sa_pbs, st, FALSE));

	/* if enabled send Pluto Vendor ID */
	if (SEND_PLUTO_VID)
	{
		if (!out_vendorid(vids_to_send-- ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE
		, &md->rbody, VID_STRONGSWAN))
		{
			return STF_INTERNAL_ERROR;
		}
	}

	/* if enabled send Cisco Unity Vendor ID */
	if (SEND_CISCO_UNITY_VID)
	{
		if (!out_vendorid(vids_to_send-- ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE
		, &md->rbody, VID_CISCO_UNITY))
		{
			return STF_INTERNAL_ERROR;
		}
	}

	/*
	 * if the peer sent an OpenPGP Vendor ID we offer the same capability
	 */
	if (md->openpgp)
	{
		if (!out_vendorid(vids_to_send-- ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE
		, &md->rbody, VID_OPENPGP))
		{
			return STF_INTERNAL_ERROR;
		}
	}

	/* Announce our ability to do eXtended AUTHentication to the peer */
	if (SEND_XAUTH_VID)
	{
		if (!out_vendorid(vids_to_send-- ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE
		, &md->rbody, VID_MISC_XAUTH))
		{
			return STF_INTERNAL_ERROR;
		}
	}

	/* Announce our ability to do Dead Peer Detection to the peer */
	if (!out_vendorid(vids_to_send-- ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE
	, &md->rbody, VID_MISC_DPD))
	{
		return STF_INTERNAL_ERROR;
	}

	if (md->nat_traversal_vid && nat_traversal_enabled)
	{
		/* reply if NAT-Traversal draft is supported */
		st->nat_traversal = nat_traversal_vid_to_method(md->nat_traversal_vid);

		if (st->nat_traversal
		&& !out_vendorid(vids_to_send-- ? ISAKMP_NEXT_VID : ISAKMP_NEXT_NONE
		, &md->rbody, md->nat_traversal_vid))
		{
			return STF_INTERNAL_ERROR;
		}
	}

	close_message(&md->rbody);

	/* save initiator SA for HASH */
	free(st->st_p1isa.ptr);
	st->st_p1isa = chunk_create(sa_pd->pbs.start, pbs_room(&sa_pd->pbs));
	st->st_p1isa = chunk_clone(st->st_p1isa);

	return STF_OK;
}

/* STATE_MAIN_I1: HDR, SA --> auth dependent
 * PSK_AUTH, DS_AUTH: --> HDR, KE, Ni
 *
 * The following are not yet implemented:
 * PKE_AUTH: --> HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
 * RPKE_AUTH: --> HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i,
 *                <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
 *
 * We must verify that the proposal received matches one we sent.
 */
stf_status main_inR1_outI2(struct msg_digest *md)
{
	struct state *const st = md->st;

	u_int8_t np = ISAKMP_NEXT_NONE;

	/* verify echoed SA */
	{
		u_int32_t ipsecdoisit;
		pb_stream proposal_pbs;
		struct isakmp_proposal proposal;
		struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];

		RETURN_STF_FAILURE(preparse_isakmp_sa_body(&sapd->payload.sa
			,&sapd->pbs, &ipsecdoisit, &proposal_pbs, &proposal));
		if (proposal.isap_notrans != 1)
		{
			loglog(RC_LOG_SERIOUS, "a single Transform is required in a selecting Oakley Proposal; found %u"
			, (unsigned)proposal.isap_notrans);
			RETURN_STF_FAILURE(BAD_PROPOSAL_SYNTAX);
		}
		RETURN_STF_FAILURE(parse_isakmp_sa_body(ipsecdoisit
			, &proposal_pbs, &proposal, NULL, st, TRUE));
	}

	if (nat_traversal_enabled && md->nat_traversal_vid)
	{
		st->nat_traversal = nat_traversal_vid_to_method(md->nat_traversal_vid);
		plog("enabling possible NAT-traversal with method %s"
			 , bitnamesof(natt_type_bitnames, st->nat_traversal));
	}
	if (st->nat_traversal & NAT_T_WITH_NATD)
	{
		np = (st->nat_traversal & NAT_T_WITH_RFC_VALUES) ?
				ISAKMP_NEXT_NATD_RFC : ISAKMP_NEXT_NATD_DRAFTS;
	}

	/**************** build output packet HDR;KE;Ni ****************/

	/* HDR out.
	 * We can't leave this to comm_handle() because the isa_np
	 * depends on the type of Auth (eventually).
	 */
	echo_hdr(md, FALSE, ISAKMP_NEXT_KE);

	/* KE out */
	if (!build_and_ship_KE(st, &st->st_gi, st->st_oakley.group
	, &md->rbody, ISAKMP_NEXT_NONCE))
		return STF_INTERNAL_ERROR;

#ifdef DEBUG
	/* Ni out */
	if (!build_and_ship_nonce(&st->st_ni, &md->rbody
	, (cur_debugging & IMPAIR_BUST_MI2)? ISAKMP_NEXT_VID : np, "Ni"))
		return STF_INTERNAL_ERROR;

	if (cur_debugging & IMPAIR_BUST_MI2)
	{
		/* generate a pointless large VID payload to push message over MTU */
		pb_stream vid_pbs;

		if (!out_generic(np, &isakmp_vendor_id_desc, &md->rbody, &vid_pbs))
			return STF_INTERNAL_ERROR;
		if (!out_zero(1500 /*MTU?*/, &vid_pbs, "Filler VID"))
			return STF_INTERNAL_ERROR;
		close_output_pbs(&vid_pbs);
	}
#else
	/* Ni out */
	if (!build_and_ship_nonce(&st->st_ni, &md->rbody, np, "Ni"))
		return STF_INTERNAL_ERROR;
#endif

	if (st->nat_traversal & NAT_T_WITH_NATD)
	{
		if (!nat_traversal_add_natd(ISAKMP_NEXT_NONE, &md->rbody, md))
			return STF_INTERNAL_ERROR;
	}

	/* finish message */
	close_message(&md->rbody);

	/* Reinsert the state, using the responder cookie we just received */
	unhash_state(st);
	memcpy(st->st_rcookie, md->hdr.isa_rcookie, COOKIE_SIZE);
	insert_state(st);   /* needs cookies, connection, and msgid (0) */

	return STF_OK;
}

/* STATE_MAIN_R1:
 * PSK_AUTH, DS_AUTH: HDR, KE, Ni --> HDR, KE, Nr
 *
 * The following are not yet implemented:
 * PKE_AUTH: HDR, KE, [ HASH(1), ] <IDi1_b>PubKey_r, <Ni_b>PubKey_r
 *          --> HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
 * RPKE_AUTH:
 *          HDR, [ HASH(1), ] <Ni_b>Pubkey_r, <KE_b>Ke_i, <IDi1_b>Ke_i [,<<Cert-I_b>Ke_i]
 *          --> HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
 */
stf_status main_inI2_outR2(struct msg_digest *md)
{
	struct state *const st = md->st;
	pb_stream *keyex_pbs = &md->chain[ISAKMP_NEXT_KE]->pbs;

	/* send CR if auth is RSA and no preloaded RSA public key exists*/
	bool RSA_auth = st->st_oakley.auth == OAKLEY_RSA_SIG
				 || st->st_oakley.auth == XAUTHInitRSA
				 || st->st_oakley.auth == XAUTHRespRSA;
	bool send_cr = !no_cr_send && RSA_auth && !has_preloaded_public_key(st);

	u_int8_t np = ISAKMP_NEXT_NONE;

	/* KE in */
	RETURN_STF_FAILURE(accept_KE(&st->st_gi, "Gi", st->st_oakley.group, keyex_pbs));

	/* Ni in */
	RETURN_STF_FAILURE(accept_nonce(md, &st->st_ni, "Ni"));

	if (st->nat_traversal & NAT_T_WITH_NATD)
	{
	   nat_traversal_natd_lookup(md);

	   np = (st->nat_traversal & NAT_T_WITH_RFC_VALUES) ?
				ISAKMP_NEXT_NATD_RFC : ISAKMP_NEXT_NATD_DRAFTS;
	}
	if (st->nat_traversal)
	{
	   nat_traversal_show_result(st->nat_traversal, md->sender_port);
	}
	if (st->nat_traversal & NAT_T_WITH_KA)
	{
	   nat_traversal_new_ka_event();
	}

	/* decode certificate requests */
	st->st_connection->got_certrequest = FALSE;
	decode_cr(md, st->st_connection);

	/**************** build output packet HDR;KE;Nr ****************/

	/* HDR out done */

	/* KE out */
	if (!build_and_ship_KE(st, &st->st_gr, st->st_oakley.group
	, &md->rbody, ISAKMP_NEXT_NONCE))
		return STF_INTERNAL_ERROR;

#ifdef DEBUG
	/* Nr out */
	if (!build_and_ship_nonce(&st->st_nr, &md->rbody
	, (cur_debugging & IMPAIR_BUST_MR2)? ISAKMP_NEXT_VID
		: (send_cr? ISAKMP_NEXT_CR : np), "Nr"))
		return STF_INTERNAL_ERROR;

	if (cur_debugging & IMPAIR_BUST_MR2)
	{
		/* generate a pointless large VID payload to push message over MTU */
		pb_stream vid_pbs;

		if (!out_generic((send_cr)? ISAKMP_NEXT_CR : np,
			&isakmp_vendor_id_desc, &md->rbody, &vid_pbs))
			return STF_INTERNAL_ERROR;
		if (!out_zero(1500 /*MTU?*/, &vid_pbs, "Filler VID"))
			return STF_INTERNAL_ERROR;
		close_output_pbs(&vid_pbs);
	}
#else
	/* Nr out */
	if (!build_and_ship_nonce(&st->st_nr, &md->rbody,
		(send_cr)? ISAKMP_NEXT_CR : np, "Nr"))
		return STF_INTERNAL_ERROR;
#endif

	/* CR out */
	if (send_cr)
	{
		if (st->st_connection->kind == CK_PERMANENT)
		{
			if (!build_and_ship_CR(CERT_X509_SIGNATURE
			, st->st_connection->spd.that.ca
			, &md->rbody, np))
				return STF_INTERNAL_ERROR;
		}
		else
		{
			generalName_t *ca = NULL;

			if (collect_rw_ca_candidates(md, &ca))
			{
				generalName_t *gn;

				for (gn = ca; gn != NULL; gn = gn->next)
				{
					if (!build_and_ship_CR(CERT_X509_SIGNATURE, gn->name
					, &md->rbody
					, gn->next == NULL ? np : ISAKMP_NEXT_CR))
						return STF_INTERNAL_ERROR;
				}
				free_generalNames(ca, FALSE);
			}
			else
			{
				if (!build_and_ship_CR(CERT_X509_SIGNATURE, chunk_empty
				, &md->rbody, np))
					return STF_INTERNAL_ERROR;
			}
		}
	}

	if (st->nat_traversal & NAT_T_WITH_NATD)
	{
	   if (!nat_traversal_add_natd(ISAKMP_NEXT_NONE, &md->rbody, md))
		   return STF_INTERNAL_ERROR;
	}

	/* finish message */
	close_message(&md->rbody);

	/* next message will be encrypted, but not this one.
	 * We could defer this calculation.
	 */
	compute_dh_shared(st, st->st_gi, st->st_oakley.group);
	if (!generate_skeyids_iv(st))
		return STF_FAIL + AUTHENTICATION_FAILED;
	update_iv(st);

	return STF_OK;
}

/* STATE_MAIN_I2:
 * SMF_PSK_AUTH: HDR, KE, Nr --> HDR*, IDi1, HASH_I
 * SMF_DS_AUTH: HDR, KE, Nr --> HDR*, IDi1, [ CERT, ] SIG_I
 *
 * The following are not yet implemented.
 * SMF_PKE_AUTH: HDR, KE, <IDr1_b>PubKey_i, <Nr_b>PubKey_i
 *          --> HDR*, HASH_I
 * SMF_RPKE_AUTH: HDR, <Nr_b>PubKey_i, <KE_b>Ke_r, <IDr1_b>Ke_r
 *          --> HDR*, HASH_I
 */
stf_status main_inR2_outI3(struct msg_digest *md)
{
	struct state *const st = md->st;
	pb_stream *const keyex_pbs = &md->chain[ISAKMP_NEXT_KE]->pbs;
	pb_stream id_pbs;   /* ID Payload; also used for hash calculation */

	certpolicy_t cert_policy = st->st_connection->spd.this.sendcert;
	cert_t mycert = st->st_connection->spd.this.cert;
	bool requested, send_cert, send_cr;

	bool RSA_auth = st->st_oakley.auth == OAKLEY_RSA_SIG
				 || st->st_oakley.auth == XAUTHInitRSA
				 || st->st_oakley.auth == XAUTHRespRSA;

	int auth_payload = RSA_auth ? ISAKMP_NEXT_SIG : ISAKMP_NEXT_HASH;

	/* KE in */
	RETURN_STF_FAILURE(accept_KE(&st->st_gr, "Gr", st->st_oakley.group, keyex_pbs));

	/* Nr in */
	RETURN_STF_FAILURE(accept_nonce(md, &st->st_nr, "Nr"));

	/* decode certificate requests */
	st->st_connection->got_certrequest = FALSE;
	decode_cr(md, st->st_connection);

	/* free collected certificate requests since as initiator
	 * we don't heed them anyway
	 */
	free_generalNames(st->st_connection->requested_ca, TRUE);
	st->st_connection->requested_ca = NULL;

	/* send certificate if auth is RSA, we have one and we want
	 * or are requested to send it
	 */
	requested = cert_policy == CERT_SEND_IF_ASKED
				&& st->st_connection->got_certrequest;
	send_cert = RSA_auth && mycert.type != CERT_NONE
				&& (cert_policy == CERT_ALWAYS_SEND || requested);

	/* send certificate request if we don't have a preloaded RSA public key */
	send_cr = !no_cr_send && send_cert && !has_preloaded_public_key(st);

	/* done parsing; initialize crypto  */
	compute_dh_shared(st, st->st_gr, st->st_oakley.group);
	if (!generate_skeyids_iv(st))
		return STF_FAIL + AUTHENTICATION_FAILED;

	if (st->nat_traversal & NAT_T_WITH_NATD)
	{
		nat_traversal_natd_lookup(md);
	}
	if (st->nat_traversal)
	{
		nat_traversal_show_result(st->nat_traversal, md->sender_port);
	}
	if (st->nat_traversal & NAT_T_WITH_KA)
	{
		nat_traversal_new_ka_event();
	}

	/*************** build output packet HDR*;IDii;HASH/SIG_I ***************/
	/* ??? NOTE: this is almost the same as main_inI3_outR3's code */

	/* HDR* out done */

	/* IDii out */
	{
		struct isakmp_ipsec_id id_hd;
		chunk_t id_b;

		build_id_payload(&id_hd, &id_b, &st->st_connection->spd.this);
		id_hd.isaiid_np = (send_cert)? ISAKMP_NEXT_CERT : auth_payload;
		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc, &md->rbody, &id_pbs)
		|| !out_chunk(id_b, &id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;
		close_output_pbs(&id_pbs);
	}

	/* CERT out */
	if (RSA_auth)
	{
		DBG(DBG_CONTROL,
			DBG_log("our certificate policy is %N", cert_policy_names, cert_policy)
		)
		if (mycert.type != CERT_NONE)
		{
			const char *request_text = "";

			if (cert_policy == CERT_SEND_IF_ASKED)
				request_text = (send_cert)? "upon request":"without request";
			plog("we have a cert %s sending it %s"
				, send_cert? "and are":"but are not", request_text);
		}
		else
		{
			plog("we don't have a cert");
		}
	}
	if (send_cert)
	{
		pb_stream cert_pbs;

		struct isakmp_cert cert_hd;
		cert_hd.isacert_np = (send_cr)? ISAKMP_NEXT_CR : ISAKMP_NEXT_SIG;
		cert_hd.isacert_type = mycert.type;

		if (!out_struct(&cert_hd, &isakmp_ipsec_certificate_desc, &md->rbody, &cert_pbs))
			return STF_INTERNAL_ERROR;
		if (!out_chunk(get_mycert(mycert), &cert_pbs, "CERT"))
			return STF_INTERNAL_ERROR;
		close_output_pbs(&cert_pbs);
	}

	/* CR out */
	if (send_cr)
	{
		if (!build_and_ship_CR(mycert.type, st->st_connection->spd.that.ca
		, &md->rbody, ISAKMP_NEXT_SIG))
			return STF_INTERNAL_ERROR;
	}

   /* HASH_I or SIG_I out */
	{
		u_char hash_val[MAX_DIGEST_LEN];
		size_t hash_len = main_mode_hash(st, hash_val, TRUE, &id_pbs);

		if (auth_payload == ISAKMP_NEXT_HASH)
		{
			/* HASH_I out */
			if (!out_generic_raw(ISAKMP_NEXT_NONE, &isakmp_hash_desc, &md->rbody
			, hash_val, hash_len, "HASH_I"))
				return STF_INTERNAL_ERROR;
		}
		else
		{
			/* SIG_I out */
			u_char sig_val[RSA_MAX_OCTETS];
			size_t sig_len = RSA_sign_hash(st->st_connection
				, sig_val, hash_val, hash_len);

			if (sig_len == 0)
			{
				loglog(RC_LOG_SERIOUS, "unable to locate my private key for RSA Signature");
				return STF_FAIL + AUTHENTICATION_FAILED;
			}

			if (!out_generic_raw(ISAKMP_NEXT_NONE, &isakmp_signature_desc
			, &md->rbody, sig_val, sig_len, "SIG_I"))
				return STF_INTERNAL_ERROR;
		}
	}

	/* encrypt message, except for fixed part of header */

	/* st_new_iv was computed by generate_skeyids_iv */
	if (!encrypt_message(&md->rbody, st))
		return STF_INTERNAL_ERROR;      /* ??? we may be partly committed */

	return STF_OK;
}

/* Shared logic for asynchronous lookup of DNS KEY records.
 * Used for STATE_MAIN_R2 and STATE_MAIN_I3.
 */

enum key_oppo_step {
	kos_null,
	kos_his_txt
#ifdef USE_KEYRR
	, kos_his_key
#endif
};

struct key_continuation {
	struct adns_continuation ac;        /* common prefix */
	struct msg_digest *md;
	enum   key_oppo_step step;
	bool                 failure_ok;
	err_t                last_ugh;
};

typedef stf_status (key_tail_fn)(struct msg_digest *md
								  , struct key_continuation *kc);

static void report_key_dns_failure(struct id *id, err_t ugh)
{
	char id_buf[BUF_LEN];       /* arbitrary limit on length of ID reported */

	(void) idtoa(id, id_buf, sizeof(id_buf));
	loglog(RC_LOG_SERIOUS, "no RSA public key known for '%s'"
		"; DNS search for KEY failed (%s)", id_buf, ugh);
}


/* Processs the Main Mode ID Payload and the Authenticator
 * (Hash or Signature Payload).
 * If a DNS query is still needed to get the other host's public key,
 * the query is initiated and STF_SUSPEND is returned.
 * Note: parameter kc is a continuation containing the results from
 * the previous DNS query, or NULL indicating no query has been issued.
 */
static stf_status
main_id_and_auth(struct msg_digest *md
				 , bool initiator       /* are we the Initiator? */
				 , cont_fn_t cont_fn    /* continuation function */
				 , const struct key_continuation *kc    /* current state, can be NULL */
)
{
	struct state *st = md->st;
	u_char hash_val[MAX_DIGEST_LEN];
	size_t hash_len;
	struct id peer;
	stf_status r = STF_OK;

	/* ID Payload in */
	if (!decode_peer_id(md, &peer))
		return STF_FAIL + INVALID_ID_INFORMATION;

	/* Hash the ID Payload.
	 * main_mode_hash requires idpl->cur to be at end of payload
	 * so we temporarily set if so.
	 */
	{
		pb_stream *idpl = &md->chain[ISAKMP_NEXT_ID]->pbs;
		u_int8_t *old_cur = idpl->cur;

		idpl->cur = idpl->roof;
		hash_len = main_mode_hash(st, hash_val, !initiator, idpl);
		idpl->cur = old_cur;
	}

	switch (st->st_oakley.auth)
	{
	case OAKLEY_PRESHARED_KEY:
	case XAUTHInitPreShared:
	case XAUTHRespPreShared:
		{
			pb_stream *const hash_pbs = &md->chain[ISAKMP_NEXT_HASH]->pbs;

			if (pbs_left(hash_pbs) != hash_len
			|| memcmp(hash_pbs->cur, hash_val, hash_len) != 0)
			{
				DBG_cond_dump(DBG_CRYPT, "received HASH:"
					, hash_pbs->cur, pbs_left(hash_pbs));
				loglog(RC_LOG_SERIOUS, "received Hash Payload does not match computed value");
				/* XXX Could send notification back */
				r = STF_FAIL + INVALID_HASH_INFORMATION;
			}
		}
		break;

	case OAKLEY_RSA_SIG:
	case XAUTHInitRSA:
	case XAUTHRespRSA:
		r = RSA_check_signature(&peer, st, hash_val, hash_len
			, &md->chain[ISAKMP_NEXT_SIG]->pbs
#ifdef USE_KEYRR
			, kc == NULL? NULL : kc->ac.keys_from_dns
#endif /* USE_KEYRR */
			, kc == NULL? NULL : kc->ac.gateways_from_dns
			);

		if (r == STF_SUSPEND)
		{
			/* initiate/resume asynchronous DNS lookup for key */
			struct key_continuation *nkc = malloc_thing(struct key_continuation);
			enum key_oppo_step step_done = kc == NULL? kos_null : kc->step;
			err_t ugh = NULL;

			/* Record that state is used by a suspended md */
			passert(st->st_suspended_md == NULL);
			st->st_suspended_md = md;

			nkc->failure_ok = FALSE;
			nkc->md = md;

			switch (step_done)
			{
			case kos_null:
				/* first try: look for the TXT records */
				nkc->step = kos_his_txt;
#ifdef USE_KEYRR
				nkc->failure_ok = TRUE;
#endif
				ugh = start_adns_query(&peer
									   , &peer  /* SG itself */
									   , T_TXT
									   , cont_fn
									   , &nkc->ac);
				break;

#ifdef USE_KEYRR
			case kos_his_txt:
				/* second try: look for the KEY records */
				nkc->step = kos_his_key;
				ugh = start_adns_query(&peer
									   , NULL   /* no sgw for KEY */
									   , T_KEY
									   , cont_fn
									   , &nkc->ac);
				break;
#endif /* USE_KEYRR */

			default:
				bad_case(step_done);
			}

			if (ugh != NULL)
			{
				report_key_dns_failure(&peer, ugh);
				st->st_suspended_md = NULL;
				r = STF_FAIL + INVALID_KEY_INFORMATION;
			}
		}
		break;

	default:
		bad_case(st->st_oakley.auth);
	}
	if (r != STF_OK)
		return r;

	DBG(DBG_CRYPT, DBG_log("authentication succeeded"));

	/*
	 * With the peer ID known, let's see if we need to switch connections.
	 */
	if (!switch_connection(md, &peer, initiator))
		return STF_FAIL + INVALID_ID_INFORMATION;

	return r;
}

/* This continuation is called as part of either
 * the main_inI3_outR3 state or main_inR3 state.
 *
 * The "tail" function is the corresponding tail
 * function main_inI3_outR3_tail | main_inR3_tail,
 * either directly when the state is started, or via
 * adns continuation.
 *
 * Basically, we go around in a circle:
 *   main_in?3* -> key_continue
 *                ^            \
 *               /              V
 *             adns            main_in?3*_tail
 *              ^               |
 *               \              V
 *                main_id_and_auth
 *
 * until such time as main_id_and_auth is able
 * to find authentication, or we run out of things
 * to try.
 */
static void key_continue(struct adns_continuation *cr, err_t ugh, 
						 key_tail_fn *tail)
{
	struct key_continuation *kc = (void *)cr;
	struct state *st = kc->md->st;

	passert(cur_state == NULL);

	/* if st == NULL, our state has been deleted -- just clean up */
	if (st != NULL)
	{
		stf_status r;

		passert(st->st_suspended_md == kc->md);
		st->st_suspended_md = NULL;     /* no longer connected or suspended */
		cur_state = st;

		if (!kc->failure_ok && ugh != NULL)
		{
			report_key_dns_failure(&st->st_connection->spd.that.id, ugh);
			r = STF_FAIL + INVALID_KEY_INFORMATION;
		}
		else
		{

#ifdef USE_KEYRR
			passert(kc->step == kos_his_txt || kc->step == kos_his_key);
#else
			passert(kc->step == kos_his_txt);
#endif
			kc->last_ugh = ugh; /* record previous error in case we need it */
			r = (*tail)(kc->md, kc);
		}
		complete_state_transition(&kc->md, r);
	}
	if (kc->md != NULL)
		release_md(kc->md);
	cur_state = NULL;
}

/* STATE_MAIN_R2:
 * PSK_AUTH: HDR*, IDi1, HASH_I --> HDR*, IDr1, HASH_R
 * DS_AUTH: HDR*, IDi1, [ CERT, ] SIG_I --> HDR*, IDr1, [ CERT, ] SIG_R
 * PKE_AUTH, RPKE_AUTH: HDR*, HASH_I --> HDR*, HASH_R
 *
 * Broken into parts to allow asynchronous DNS lookup.
 *
 * - main_inI3_outR3 to start
 * - main_inI3_outR3_tail to finish or suspend for DNS lookup
 * - main_inI3_outR3_continue to start main_inI3_outR3_tail again
 */
static key_tail_fn main_inI3_outR3_tail;        /* forward */

stf_status main_inI3_outR3(struct msg_digest *md)
{
	return main_inI3_outR3_tail(md, NULL);
}

static void main_inI3_outR3_continue(struct adns_continuation *cr, err_t ugh)
{
	key_continue(cr, ugh, main_inI3_outR3_tail);
}

static stf_status
main_inI3_outR3_tail(struct msg_digest *md
, struct key_continuation *kc)
{
	struct state *const st = md->st;
	u_int8_t auth_payload;
	pb_stream r_id_pbs; /* ID Payload; also used for hash calculation */
	certpolicy_t cert_policy;
	cert_t mycert;
	bool RSA_auth;
	bool send_cert;
	bool requested;

	/* ID and HASH_I or SIG_I in
	 * Note: this may switch the connection being used!
	 */
	{
		stf_status r = main_id_and_auth(md, FALSE
										, main_inI3_outR3_continue
										, kc);

		if (r != STF_OK)
			return r;
	}

	/* send certificate if auth is RSA, we have one and we want
	 * or are requested to send it
	 */
	cert_policy = st->st_connection->spd.this.sendcert;
	mycert = st->st_connection->spd.this.cert;
	requested = cert_policy == CERT_SEND_IF_ASKED
				&& st->st_connection->got_certrequest;
	RSA_auth = st->st_oakley.auth == OAKLEY_RSA_SIG
			|| st->st_oakley.auth == XAUTHInitRSA
			|| st->st_oakley.auth == XAUTHRespRSA;
	send_cert = RSA_auth
				&& mycert.type != CERT_NONE
				&& (cert_policy == CERT_ALWAYS_SEND || requested);

	/*************** build output packet HDR*;IDir;HASH/SIG_R ***************/
	/* proccess_packet() would automatically generate the HDR*
	 * payload if smc->first_out_payload is not ISAKMP_NEXT_NONE.
	 * We don't do this because we wish there to be no partially
	 * built output packet if we need to suspend for asynch DNS.
	 */
	/* ??? NOTE: this is almost the same as main_inR2_outI3's code */

	/* HDR* out
	 * If auth were PKE_AUTH or RPKE_AUTH, ISAKMP_NEXT_HASH would
	 * be first payload.
	 */
	echo_hdr(md, TRUE, ISAKMP_NEXT_ID);

	auth_payload = RSA_auth ? ISAKMP_NEXT_SIG : ISAKMP_NEXT_HASH;

	/* IDir out */
	{
		/* id_hd should be struct isakmp_id, but struct isakmp_ipsec_id
		 * allows build_id_payload() to work for both phases.
		 */
		struct isakmp_ipsec_id id_hd;
		chunk_t id_b;

		build_id_payload(&id_hd, &id_b, &st->st_connection->spd.this);
		id_hd.isaiid_np = (send_cert)? ISAKMP_NEXT_CERT : auth_payload;
		if (!out_struct(&id_hd, &isakmp_ipsec_identification_desc, &md->rbody, &r_id_pbs)
		|| !out_chunk(id_b, &r_id_pbs, "my identity"))
			return STF_INTERNAL_ERROR;
		close_output_pbs(&r_id_pbs);
	}

	/* CERT out */
	if (RSA_auth)
	{
		DBG(DBG_CONTROL,
			DBG_log("our certificate policy is %N", cert_policy_names, cert_policy)
		)
		if (mycert.type != CERT_NONE)
		{
			const char *request_text = "";

			if (cert_policy == CERT_SEND_IF_ASKED)
				request_text = (send_cert)? "upon request":"without request";
			plog("we have a cert %s sending it %s"
				, send_cert? "and are":"but are not", request_text);
		}
		else
		{
			plog("we don't have a cert");
		}
	}
	if (send_cert)
	{
		pb_stream cert_pbs;

		struct isakmp_cert cert_hd;
		cert_hd.isacert_np = ISAKMP_NEXT_SIG;
		cert_hd.isacert_type = mycert.type;

		if (!out_struct(&cert_hd, &isakmp_ipsec_certificate_desc, &md->rbody, &cert_pbs))
		return STF_INTERNAL_ERROR;
		if (!out_chunk(get_mycert(mycert), &cert_pbs, "CERT"))
			return STF_INTERNAL_ERROR;
		close_output_pbs(&cert_pbs);
	}

	/* HASH_R or SIG_R out */
	{
		u_char hash_val[MAX_DIGEST_LEN];
		size_t hash_len = main_mode_hash(st, hash_val, FALSE, &r_id_pbs);

		if (auth_payload == ISAKMP_NEXT_HASH)
		{
			/* HASH_R out */
			if (!out_generic_raw(ISAKMP_NEXT_NONE, &isakmp_hash_desc, &md->rbody
			, hash_val, hash_len, "HASH_R"))
				return STF_INTERNAL_ERROR;
		}
		else
		{
			/* SIG_R out */
			u_char sig_val[RSA_MAX_OCTETS];
			size_t sig_len = RSA_sign_hash(st->st_connection
				, sig_val, hash_val, hash_len);

			if (sig_len == 0)
			{
				loglog(RC_LOG_SERIOUS, "unable to locate my private key for RSA Signature");
				return STF_FAIL + AUTHENTICATION_FAILED;
			}

			if (!out_generic_raw(ISAKMP_NEXT_NONE, &isakmp_signature_desc
			, &md->rbody, sig_val, sig_len, "SIG_R"))
				return STF_INTERNAL_ERROR;
		}
	}

	/* encrypt message, sans fixed part of header */

	if (!encrypt_message(&md->rbody, st))
		return STF_INTERNAL_ERROR;      /* ??? we may be partly committed */

	/* Last block of Phase 1 (R3), kept for Phase 2 IV generation */
	DBG_cond_dump(DBG_CRYPT, "last encrypted block of Phase 1:"
		, st->st_new_iv, st->st_new_iv_len);

	ISAKMP_SA_established(st->st_connection, st->st_serialno);

	/* Save Phase 1 IV */
	st->st_ph1_iv_len = st->st_new_iv_len;
	set_ph1_iv(st, st->st_new_iv);

	return STF_OK;
}

/* STATE_MAIN_I3:
 * Handle HDR*;IDir;HASH/SIG_R from responder.
 *
 * Broken into parts to allow asynchronous DNS for KEY records.
 *
 * - main_inR3 to start
 * - main_inR3_tail to finish or suspend for DNS lookup
 * - main_inR3_continue to start main_inR3_tail again
 */

static key_tail_fn main_inR3_tail;      /* forward */

stf_status main_inR3(struct msg_digest *md)
{
	return main_inR3_tail(md, NULL);
}

static void main_inR3_continue(struct adns_continuation *cr, err_t ugh)
{
	key_continue(cr, ugh, main_inR3_tail);
}

static stf_status main_inR3_tail(struct msg_digest *md,
								 struct key_continuation *kc)
{
	struct state *const st = md->st;

	/* ID and HASH_R or SIG_R in
	 * Note: this may switch the connection being used!
	 */
	{
		stf_status r = main_id_and_auth(md, TRUE, main_inR3_continue, kc);

		if (r != STF_OK)
			return r;
	}

	/**************** done input ****************/

	ISAKMP_SA_established(st->st_connection, st->st_serialno);

	/* Save Phase 1 IV */
	st->st_ph1_iv_len = st->st_new_iv_len;
	set_ph1_iv(st, st->st_new_iv);


	update_iv(st);      /* finalize our Phase 1 IV */

	return STF_OK;
}

/* Handle first message of Phase 2 -- Quick Mode.
 * HDR*, HASH(1), SA, Ni [, KE ] [, IDci, IDcr ] -->
 * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ]
 * (see RFC 2409 "IKE" 5.5)
 * Installs inbound IPsec SAs.
 * Although this seems early, we know enough to do so, and
 * this way we know that it is soon enough to catch all
 * packets that other side could send using this IPsec SA.
 *
 * Broken into parts to allow asynchronous DNS for TXT records:
 *
 * - quick_inI1_outR1 starts the ball rolling.
 *   It checks and parses enough to learn the Phase 2 IDs
 *
 * - quick_inI1_outR1_tail does the rest of the job
 *   unless DNS must be consulted.  In that case,
 *   it starts a DNS query, salts away what is needed
 *   to continue, and suspends.  Calls
 *   + quick_inI1_outR1_start_query
 *   + quick_inI1_outR1_process_answer
 *
 * - quick_inI1_outR1_continue will restart quick_inI1_outR1_tail
 *   when DNS comes back with an answer.
 *
 * A big chunk of quick_inI1_outR1_tail is executed twice.
 * This is necessary because the set of connections
 * might change while we are awaiting DNS.
 * When first called, gateways_from_dns == NULL.  If DNS is
 * consulted asynchronously, gateways_from_dns != NULL the second time.
 * Remember that our state object might disappear too!
 *
 *
 * If the connection is opportunistic, we must verify delegation.
 *
 * 1. Check that we are authorized to be SG for
 *    our client.  We look for the TXT record that
 *    delegates us.  We also check that the public
 *    key (if present) matches the private key we used.
 *    Eventually, we should probably require DNSsec
 *    authentication for our side.
 *
 * 2. If our client TXT record did not include a
 *    public key, check the KEY record indicated
 *    by the identity in the TXT record.
 *
 * 3. If the peer's client is the peer itself, we
 *    consider it authenticated.  Otherwise, we check
 *    the TXT record for the client to see that
 *    the identity of the SG matches the peer and
 *    that some public key (if present in the TXT)
 *    matches.  We need not check the public key if
 *    it isn't in the TXT record.
 *
 * Since p isn't yet instantiated, we need to look
 * in c for description of peer.
 *
 * We cannot afford to block waiting for a DNS query.
 * The code here is structured as two halves:
 * - process the result of just completed
 *   DNS query (if any)
 * - if another query is needed, initiate the next
 *   DNS query and suspend
 */

enum verify_oppo_step {
	vos_fail,
	vos_start,
	vos_our_client,
	vos_our_txt,
#ifdef USE_KEYRR
	vos_our_key,
#endif /* USE_KEYRR */
	vos_his_client,
	vos_done
};

static const char *const verify_step_name[] = {
  "vos_fail",
  "vos_start",
  "vos_our_client",
  "vos_our_txt",
#ifdef USE_KEYRR
  "vos_our_key",
#endif /* USE_KEYRR */
  "vos_his_client",
  "vos_done"
};

/* hold anything we can handle of a Phase 2 ID */
struct p2id {
	ip_subnet net;
	u_int8_t proto;
	u_int16_t port;
};

struct verify_oppo_bundle {
	enum verify_oppo_step step;
	bool failure_ok;      /* if true, quick_inI1_outR1_continue will try
						   * other things on DNS failure */
	struct msg_digest *md;
	struct p2id my, his;
	unsigned int new_iv_len;    /* p1st's might change */
	u_char new_iv[MAX_DIGEST_LEN];
	/* int whackfd; */  /* not needed because we are Responder */
};

struct verify_oppo_continuation {
	struct adns_continuation ac;        /* common prefix */
	struct verify_oppo_bundle b;
};

static stf_status quick_inI1_outR1_tail(struct verify_oppo_bundle *b
	, struct adns_continuation *ac);

stf_status quick_inI1_outR1(struct msg_digest *md)
{
	const struct state *const p1st = md->st;
	struct connection *c = p1st->st_connection;
	struct payload_digest *const id_pd = md->chain[ISAKMP_NEXT_ID];
	struct verify_oppo_bundle b;

	/* HASH(1) in */
	CHECK_QUICK_HASH(md
		, quick_mode_hash12(hash_val, hash_pbs->roof, md->message_pbs.roof
			, p1st, &md->hdr.isa_msgid, FALSE)
		, "HASH(1)", "Quick I1");

	/* [ IDci, IDcr ] in
	 * We do this now (probably out of physical order) because
	 * we wish to select the correct connection before we consult
	 * it for policy.
	 */

	if (id_pd != NULL)
	{
		/* ??? we are assuming IPSEC_DOI */

		/* IDci (initiator is peer) */

		if (!decode_net_id(&id_pd->payload.ipsec_id, &id_pd->pbs
		, &b.his.net, "peer client"))
			return STF_FAIL + INVALID_ID_INFORMATION;

		/* Hack for MS 818043 NAT-T Update */

		if (id_pd->payload.ipsec_id.isaiid_idtype == ID_FQDN)
			happy(addrtosubnet(&c->spd.that.host_addr, &b.his.net));

		/* End Hack for MS 818043 NAT-T Update */

		b.his.proto = id_pd->payload.ipsec_id.isaiid_protoid;
		b.his.port = id_pd->payload.ipsec_id.isaiid_port;
		b.his.net.addr.u.v4.sin_port = htons(b.his.port);

		/* IDcr (we are responder) */

		if (!decode_net_id(&id_pd->next->payload.ipsec_id, &id_pd->next->pbs
		, &b.my.net, "our client"))
			return STF_FAIL + INVALID_ID_INFORMATION;
		
		b.my.proto = id_pd->next->payload.ipsec_id.isaiid_protoid;
		b.my.port = id_pd->next->payload.ipsec_id.isaiid_port;
		b.my.net.addr.u.v4.sin_port = htons(b.my.port);
	}
	else
	{
		/* implicit IDci and IDcr: peer and self */
		if (!sameaddrtype(&c->spd.this.host_addr, &c->spd.that.host_addr))
			return STF_FAIL;

		happy(addrtosubnet(&c->spd.this.host_addr, &b.my.net));
		happy(addrtosubnet(&c->spd.that.host_addr, &b.his.net));
		b.his.proto = b.my.proto = 0;
		b.his.port = b.my.port = 0;
	}
	b.step = vos_start;
	b.md = md;
	b.new_iv_len = p1st->st_new_iv_len;
	memcpy(b.new_iv, p1st->st_new_iv, p1st->st_new_iv_len);
	return quick_inI1_outR1_tail(&b, NULL);
}

static void
report_verify_failure(struct verify_oppo_bundle *b, err_t ugh)
{
	struct state *st = b->md->st;
	char fgwb[ADDRTOT_BUF]
		, cb[ADDRTOT_BUF];
	ip_address client;
	err_t which = NULL;

	switch (b->step)
	{
	case vos_our_client:
	case vos_our_txt:
#ifdef USE_KEYRR
	case vos_our_key:
#endif /* USE_KEYRR */
		which = "our";
		networkof(&b->my.net, &client);
		break;

	case vos_his_client:
		which = "his";
		networkof(&b->his.net, &client);
		break;

	case vos_start:
	case vos_done:
	case vos_fail:
	default:
		bad_case(b->step);
	}

	addrtot(&st->st_connection->spd.that.host_addr, 0, fgwb, sizeof(fgwb));
	addrtot(&client, 0, cb, sizeof(cb));
	loglog(RC_OPPOFAILURE
		, "gateway %s wants connection with %s as %s client, but DNS fails to confirm delegation: %s"
		, fgwb, cb, which, ugh);
}

static void quick_inI1_outR1_continue(struct adns_continuation *cr, err_t ugh)
{
	stf_status r;
	struct verify_oppo_continuation *vc = (void *)cr;
	struct verify_oppo_bundle *b = &vc->b;
	struct state *st = b->md->st;

	passert(cur_state == NULL);
	/* if st == NULL, our state has been deleted -- just clean up */
	if (st != NULL)
	{
		passert(st->st_suspended_md == b->md);
		st->st_suspended_md = NULL;     /* no longer connected or suspended */
		cur_state = st;
		if (!b->failure_ok && ugh != NULL)
		{
			report_verify_failure(b, ugh);
			r = STF_FAIL + INVALID_ID_INFORMATION;
		}
		else
		{
			r = quick_inI1_outR1_tail(b, cr);
		}
		complete_state_transition(&b->md, r);
	}
	if (b->md != NULL)
		release_md(b->md);
	cur_state = NULL;
}

static stf_status quick_inI1_outR1_start_query(struct verify_oppo_bundle *b,
											   enum verify_oppo_step next_step)
{
	struct msg_digest *md = b->md;
	struct state *p1st = md->st;
	struct connection *c = p1st->st_connection;
	struct verify_oppo_continuation *vc = malloc_thing(struct verify_oppo_continuation);
	struct id id        /* subject of query */
		, *our_id       /* needed for myid playing */
		, our_id_space; /* ephemeral: no need for unshare_id_content */
	ip_address client;
	err_t ugh = NULL;

	/* Record that state is used by a suspended md */
	b->step = next_step;    /* not just vc->b.step */
	vc->b = *b;
	passert(p1st->st_suspended_md == NULL);
	p1st->st_suspended_md = b->md;

	DBG(DBG_CONTROL,
		{
			char ours[SUBNETTOT_BUF];
			char his[SUBNETTOT_BUF];

			subnettot(&c->spd.this.client, 0, ours, sizeof(ours));
			subnettot(&c->spd.that.client, 0, his, sizeof(his));

			DBG_log("responding with DNS query - from %s to %s new state: %s"
					, ours, his, verify_step_name[b->step]);
		});

	/* Resolve %myid in a cheesy way.
	 * We have to do the resolution because start_adns_query
	 * et al have insufficient information to do so.
	 * If %myid is already known, we'll use that value
	 * (XXX this may be a mistake: it could be stale).
	 * If %myid is unknown, we should check to see if
	 * there are credentials for the IP address or the FQDN.
	 * Instead, we'll just assume the IP address since we are
	 * acting as the responder and only the IP address would
	 * have gotten it to us.
	 * We don't even try to do this for the other side:
	 * %myid makes no sense for the other side (but it is syntactically
	 * legal).
	 */
	our_id = resolve_myid(&c->spd.this.id);
	if (our_id->kind == ID_NONE)
	{
		iptoid(&c->spd.this.host_addr, &our_id_space);
		our_id = &our_id_space;
	}

	switch (next_step)
	{
	case vos_our_client:
		networkof(&b->my.net, &client);
		iptoid(&client, &id);
		vc->b.failure_ok = b->failure_ok = FALSE;
		ugh = start_adns_query(&id
			, our_id
			, T_TXT
			, quick_inI1_outR1_continue
			, &vc->ac);
		break;

	case vos_our_txt:
		vc->b.failure_ok = b->failure_ok = TRUE;
		ugh = start_adns_query(our_id
			, our_id    /* self as SG */
			, T_TXT
			, quick_inI1_outR1_continue
			, &vc->ac);
		break;

#ifdef USE_KEYRR
	case vos_our_key:
		vc->b.failure_ok = b->failure_ok = FALSE;
		ugh = start_adns_query(our_id
			, NULL
			, T_KEY
			, quick_inI1_outR1_continue
			, &vc->ac);
		break;
#endif

	case vos_his_client:
		networkof(&b->his.net, &client);
		iptoid(&client, &id);
		vc->b.failure_ok = b->failure_ok = FALSE;
		ugh = start_adns_query(&id
			, &c->spd.that.id
			, T_TXT
			, quick_inI1_outR1_continue
			, &vc->ac);
		break;

	default:
		bad_case(next_step);
	}

	if (ugh != NULL)
	{
		/* note: we'd like to use vc->b but vc has been freed
		 * so we have to use b.  This is why we plunked next_state
		 * into b, not just vc->b.
		 */
		report_verify_failure(b, ugh);
		p1st->st_suspended_md = NULL;
		return STF_FAIL + INVALID_ID_INFORMATION;
	}
	else
	{
		return STF_SUSPEND;
	}
}

static enum verify_oppo_step quick_inI1_outR1_process_answer(
										struct verify_oppo_bundle *b,
										struct adns_continuation *ac,
										struct state *p1st)
{
	struct connection *c = p1st->st_connection;
	enum verify_oppo_step next_step = vos_our_client;
	err_t ugh = NULL;

	DBG(DBG_CONTROL,
		{
			char ours[SUBNETTOT_BUF];
			char his[SUBNETTOT_BUF];

			subnettot(&c->spd.this.client, 0, ours, sizeof(ours));
			subnettot(&c->spd.that.client, 0, his, sizeof(his));
			DBG_log("responding on demand from %s to %s state: %s"
					, ours, his, verify_step_name[b->step]);
		});

	/* process just completed DNS query (if any) */
	switch (b->step)
	{
	case vos_start:
		/* no query to digest */
		next_step = vos_our_client;
		break;

	case vos_our_client:
		next_step = vos_his_client;
		{
			const struct RSA_private_key *pri = get_RSA_private_key(c);
			struct gw_info *gwp;

			if (pri == NULL)
			{
				ugh = "we don't know our own key";
				break;
			}
			ugh = "our client does not delegate us as its Security Gateway";
			for (gwp = ac->gateways_from_dns; gwp != NULL; gwp = gwp->next)
			{
				ugh = "our client delegates us as its Security Gateway but with the wrong public key";
				/* If there is no key in the TXT record,
				 * we count it as a win, but we will have
				 * to separately fetch and check the KEY record.
				 * If there is a key from the TXT record,
				 * we count it as a win if we match the key.
				 */
				if (!gwp->gw_key_present)
				{
					next_step = vos_our_txt;
					ugh = NULL; /* good! */
					break;
				}
				else if (same_RSA_public_key(&pri->pub, &gwp->key->u.rsa))
				{
					ugh = NULL; /* good! */
					break;
				}
			}
		}
		break;

	case vos_our_txt:
		next_step = vos_his_client;
		{
			const struct RSA_private_key *pri = get_RSA_private_key(c);

			if (pri == NULL)
			{
				ugh = "we don't know our own key";
				break;
			}
			{
				struct gw_info *gwp;

				for (gwp = ac->gateways_from_dns; gwp != NULL; gwp = gwp->next)
				{
#ifdef USE_KEYRR
					/* not an error yet, because we have to check KEY RR as well */
					ugh = NULL;
#else
					ugh = "our client delegation depends on our " RRNAME " record, but it has the wrong public key";
#endif
					if (gwp->gw_key_present
					&& same_RSA_public_key(&pri->pub, &gwp->key->u.rsa))
					{
						ugh = NULL;     /* good! */
						break;
					}
#ifdef USE_KEYRR
					next_step = vos_our_key;
#endif
				}
			}
		}
		break;

#ifdef USE_KEYRR
	case vos_our_key:
		next_step = vos_his_client;
		{
			const struct RSA_private_key *pri = get_RSA_private_key(c);

			if (pri == NULL)
			{
				ugh = "we don't know our own key";
				break;
			}
			{
				pubkey_list_t *kp;

				ugh = "our client delegation depends on our missing " RRNAME " record";
				for (kp = ac->keys_from_dns; kp != NULL; kp = kp->next)
				{
					ugh = "our client delegation depends on our " RRNAME " record, but it has the wrong public key";
					if (same_RSA_public_key(&pri->pub, &kp->key->u.rsa))
					{
						/* do this only once a day */
						if (!logged_txt_warning)
						{
							loglog(RC_LOG_SERIOUS, "found KEY RR but not TXT RR. See http://www.freeswan.org/err/txt-change.html.");
							logged_txt_warning = TRUE;
						}
						ugh = NULL;     /* good! */
						break;
					}
				}
			}
		}
		break;
#endif /* USE_KEYRR */

	case vos_his_client:
		next_step = vos_done;
		{
			struct gw_info *gwp;

			/* check that the public key that authenticated
			 * the ISAKMP SA (p1st) will do for this gateway.
			 */

			ugh = "peer's client does not delegate to peer";
			for (gwp = ac->gateways_from_dns; gwp != NULL; gwp = gwp->next)
			{
				ugh = "peer and its client disagree about public key";
				/* If there is a key from the TXT record,
				 * we count it as a win if we match the key.
				 * If there was no key, we claim a match since
				 * it implies fetching a KEY from the same
				 * place we must have gotten it.
				 */
				if (!gwp->gw_key_present
				|| same_RSA_public_key(&p1st->st_peer_pubkey->u.rsa
				, &gwp->key->u.rsa))
				{
					ugh = NULL; /* good! */
					break;
				}
			}
		}
		break;

	default:
		bad_case(b->step);
	}

	if (ugh != NULL)
	{
		report_verify_failure(b, ugh);
		next_step = vos_fail;
	}
	return next_step;
}

static stf_status quick_inI1_outR1_tail(struct verify_oppo_bundle *b,
										struct adns_continuation *ac)
{
	struct msg_digest *md = b->md;
	struct state *const p1st = md->st;
	struct connection *c = p1st->st_connection;
	struct payload_digest *const id_pd = md->chain[ISAKMP_NEXT_ID];
	ip_subnet *our_net = &b->my.net
		, *his_net = &b->his.net;

	u_char      /* set by START_HASH_PAYLOAD: */
		*r_hashval,     /* where in reply to jam hash value */
		*r_hash_start;  /* from where to start hashing */

	/* Now that we have identities of client subnets, we must look for
	 * a suitable connection (our current one only matches for hosts).
	 */
	{
		struct connection *p = find_client_connection(c
			, our_net, his_net, b->my.proto, b->my.port, b->his.proto, b->his.port);

		if (p == NULL)
		{
			/* This message occurs in very puzzling circumstances
			 * so we must add as much information and beauty as we can.
			 */
			struct end
				me = c->spd.this,
				he = c->spd.that;
			char buf[2*SUBNETTOT_BUF + 2*ADDRTOT_BUF + 2*BUF_LEN + 2*ADDRTOT_BUF + 12]; /* + 12 for separating */
			size_t l;

			me.client = *our_net;
			me.has_client = !subnetisaddr(our_net, &me.host_addr);
			me.protocol = b->my.proto;
			me.port = b->my.port;

			he.client = *his_net;
			he.has_client = !subnetisaddr(his_net, &he.host_addr);
			he.protocol = b->his.proto;
			he.port = b->his.port;

			l = format_end(buf, sizeof(buf), &me, NULL, TRUE, LEMPTY);
			l += snprintf(buf + l, sizeof(buf) - l, "...");
			(void)format_end(buf + l, sizeof(buf) - l, &he, NULL, FALSE, LEMPTY);
			plog("cannot respond to IPsec SA request"
				" because no connection is known for %s"
				, buf);
			return STF_FAIL + INVALID_ID_INFORMATION;
		}
		else if (p != c)
		{
			/* We've got a better connection: it can support the
			 * specified clients.  But it may need instantiation.
			 */
			if (p->kind == CK_TEMPLATE)
			{
				/* Yup, it needs instantiation.  How much?
				 * Is it a Road Warrior connection (simple)
				 * or is it an Opportunistic connection (needing gw validation)?
				 */
				if (p->policy & POLICY_OPPO)
				{
					/* Opportunistic case: delegation must be verified.
					 * Here be dragons.
					 */
					enum verify_oppo_step next_step;
					ip_address our_client, his_client;

					passert(subnetishost(our_net) && subnetishost(his_net));
					networkof(our_net, &our_client);
					networkof(his_net, &his_client);

					next_step = quick_inI1_outR1_process_answer(b, ac, p1st);
					if (next_step == vos_fail)
						return STF_FAIL + INVALID_ID_INFORMATION;

					/* short circuit: if peer's client is self,
					 * accept that we've verified delegation in Phase 1
					 */
					if (next_step == vos_his_client
					&& sameaddr(&c->spd.that.host_addr, &his_client))
						next_step = vos_done;

					/* the second chunk: initiate the next DNS query (if any) */
					DBG(DBG_CONTROL,
						{
							char ours[SUBNETTOT_BUF];
							char his[SUBNETTOT_BUF];

							subnettot(&c->spd.this.client, 0, ours, sizeof(ours));
							subnettot(&c->spd.that.client, 0, his, sizeof(his));

							DBG_log("responding on demand from %s to %s new state: %s"
									, ours, his, verify_step_name[next_step]);
						});

					/* start next DNS query and suspend (if necessary) */
					if (next_step != vos_done)
						return quick_inI1_outR1_start_query(b, next_step);

					/* Instantiate inbound Opportunistic connection,
					 * carrying over authenticated peer ID
					 * and filling in a few more details.
					 * We used to include gateways_from_dns, but that
					 * seems pointless at this stage of negotiation.
					 * We should record DNS sec use, if any -- belongs in
					 * state during perhaps.
					 */
					p = oppo_instantiate(p, &c->spd.that.host_addr, &c->spd.that.id
						, NULL, &our_client, &his_client);
				}
				else
				{
					/* Plain Road Warrior:
					 * instantiate, carrying over authenticated peer ID
					 */
					p = rw_instantiate(p, &c->spd.that.host_addr, md->sender_port
								, his_net, &c->spd.that.id);
				}
			}
#ifdef DEBUG
			/* temporarily bump up cur_debugging to get "using..." message
			 * printed if we'd want it with new connection.
			 */
			{
				lset_t old_cur_debugging = cur_debugging;

				cur_debugging |= p->extra_debugging;
				DBG(DBG_CONTROL, DBG_log("using connection \"%s\"", p->name));
				cur_debugging = old_cur_debugging;
			}
#endif
			c = p;
		}
		/* fill in the client's true ip address/subnet */
		if (p->spd.that.has_client_wildcard)
		{
			p->spd.that.client = *his_net;
			p->spd.that.has_client_wildcard = FALSE;
		}
		else if (is_virtual_connection(c))
		{
			c->spd.that.client = *his_net;
			c->spd.that.virt = NULL;
			if (subnetishost(his_net) && addrinsubnet(&c->spd.that.host_addr, his_net))
				c->spd.that.has_client = FALSE;
		}

		/* fill in the client's true port */
		if (p->spd.that.has_port_wildcard)
		{
			int port = htons(b->his.port);

			setportof(port, &p->spd.that.host_addr);
			setportof(port, &p->spd.that.client.addr);

			p->spd.that.port = b->his.port;
			p->spd.that.has_port_wildcard = FALSE;
		}
	}

	/* now that we are sure of our connection, create our new state */
	{
		struct state *const st = duplicate_state(p1st);

		/* first: fill in missing bits of our new state object
		 * note: we don't copy over st_peer_pubkey, the public key
		 * that authenticated the ISAKMP SA.  We only need it in this
		 * routine, so we can "reach back" to p1st to get it.
		 */

		if (st->st_connection != c)
		{
			struct connection *t = st->st_connection;

			st->st_connection = c;
			set_cur_connection(c);
			connection_discard(t);
		}

		st->st_try = 0; /* not our job to try again from start */

		st->st_msgid = md->hdr.isa_msgid;

		st->st_new_iv_len = b->new_iv_len;
		memcpy(st->st_new_iv, b->new_iv, b->new_iv_len);

		set_cur_state(st);      /* (caller will reset) */
		md->st = st;    /* feed back new state */

		st->st_peeruserprotoid = b->his.proto;
		st->st_peeruserport = b->his.port;
		st->st_myuserprotoid = b->my.proto;
		st->st_myuserport = b->my.port;

		insert_state(st);       /* needs cookies, connection, and msgid */

		/* copy the connection's
		 * IPSEC policy into our state.  The ISAKMP policy is water under
		 * the bridge, I think.  It will reflect the ISAKMP SA that we
		 * are using.
		 */
		st->st_policy = (p1st->st_policy & POLICY_ISAKMP_MASK)
			| (c->policy & ~POLICY_ISAKMP_MASK);

		if (p1st->nat_traversal & NAT_T_DETECTED)
		{
			st->nat_traversal = p1st->nat_traversal;
			nat_traversal_change_port_lookup(md, md->st);
		}
		else
		{
			st->nat_traversal = 0;
		}
		if ((st->nat_traversal & NAT_T_DETECTED)
		&&  (st->nat_traversal & NAT_T_WITH_NATOA))
		{
			nat_traversal_natoa_lookup(md);
		}

		/* Start the output packet.
		 *
		 * proccess_packet() would automatically generate the HDR*
		 * payload if smc->first_out_payload is not ISAKMP_NEXT_NONE.
		 * We don't do this because we wish there to be no partially
		 * built output packet if we need to suspend for asynch DNS.
		 *
		 * We build the reply packet as we parse the message since
		 * the parse_ipsec_sa_body emits the reply SA
		 */

		/* HDR* out */
		echo_hdr(md, TRUE, ISAKMP_NEXT_HASH);

		/* HASH(2) out -- first pass */
		START_HASH_PAYLOAD(md->rbody, ISAKMP_NEXT_SA);

		/* process SA (in and out) */
		{
			struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];
			pb_stream r_sa_pbs;
			struct isakmp_sa sa = sapd->payload.sa;

			/* sa header is unchanged -- except for np */
			sa.isasa_np = ISAKMP_NEXT_NONCE;
			if (!out_struct(&sa, &isakmp_sa_desc, &md->rbody, &r_sa_pbs))
				return STF_INTERNAL_ERROR;

			/* parse and accept body */
			st->st_pfs_group = &unset_group;
			RETURN_STF_FAILURE(parse_ipsec_sa_body(&sapd->pbs
					, &sapd->payload.sa, &r_sa_pbs, FALSE, st));
		}

		passert(st->st_pfs_group != &unset_group);

		if ((st->st_policy & POLICY_PFS) && st->st_pfs_group == NULL)
		{
			loglog(RC_LOG_SERIOUS, "we require PFS but Quick I1 SA specifies no GROUP_DESCRIPTION");
			return STF_FAIL + NO_PROPOSAL_CHOSEN;       /* ??? */
		}

		/* Ni in */
		RETURN_STF_FAILURE(accept_nonce(md, &st->st_ni, "Ni"));

		/* [ KE ] in (for PFS) */
		RETURN_STF_FAILURE(accept_PFS_KE(md, &st->st_gi, "Gi", "Quick Mode I1"));

		plog("responding to Quick Mode");

		/**** finish reply packet: Nr [, KE ] [, IDci, IDcr ] ****/

		/* Nr out */
		if (!build_and_ship_nonce(&st->st_nr, &md->rbody
		, st->st_pfs_group != NULL? ISAKMP_NEXT_KE : id_pd != NULL? ISAKMP_NEXT_ID : ISAKMP_NEXT_NONE
		, "Nr"))
			return STF_INTERNAL_ERROR;

		/* [ KE ] out (for PFS) */

		if (st->st_pfs_group != NULL)
		{
			if (!build_and_ship_KE(st, &st->st_gr, st->st_pfs_group
			, &md->rbody, id_pd != NULL? ISAKMP_NEXT_ID : ISAKMP_NEXT_NONE))
					return STF_INTERNAL_ERROR;

			/* MPZ-Operations might be done after sending the packet... */
			compute_dh_shared(st, st->st_gi, st->st_pfs_group);
		}

		/* [ IDci, IDcr ] out */
		if  (id_pd != NULL)
		{
			struct isakmp_ipsec_id *p = (void *)md->rbody.cur;  /* UGH! */

			if (!out_raw(id_pd->pbs.start, pbs_room(&id_pd->pbs), &md->rbody, "IDci"))
				return STF_INTERNAL_ERROR;
			p->isaiid_np = ISAKMP_NEXT_ID;

			p = (void *)md->rbody.cur;  /* UGH! */

			if (!out_raw(id_pd->next->pbs.start, pbs_room(&id_pd->next->pbs), &md->rbody, "IDcr"))
				return STF_INTERNAL_ERROR;
			p->isaiid_np = ISAKMP_NEXT_NONE;
		}

		if ((st->nat_traversal & NAT_T_WITH_NATOA)
		&& (st->nat_traversal & LELEM(NAT_TRAVERSAL_NAT_BHND_ME))
		&& (st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TRANSPORT))
		{
			/** Send NAT-OA if our address is NATed and if we use Transport Mode */
			if (!nat_traversal_add_natoa(ISAKMP_NEXT_NONE, &md->rbody, md->st))
			{
				return STF_INTERNAL_ERROR;
			}
		}
		if ((st->nat_traversal & NAT_T_DETECTED)
		&& (st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TRANSPORT)
		&& (c->spd.that.has_client))
		{
			/** Remove client **/
			addrtosubnet(&c->spd.that.host_addr, &c->spd.that.client);
			c->spd.that.has_client = FALSE;
		}

		/* Compute reply HASH(2) and insert in output */
		(void)quick_mode_hash12(r_hashval, r_hash_start, md->rbody.cur
			, st, &st->st_msgid, TRUE);

		/* Derive new keying material */
		compute_keymats(st);

		/* Tell the kernel to establish the new inbound SA
		 * (unless the commit bit is set -- which we don't support).
		 * We do this before any state updating so that
		 * failure won't look like success.
		 */
		if (!install_inbound_ipsec_sa(st))
			return STF_INTERNAL_ERROR;  /* ??? we may be partly committed */

		/* encrypt message, except for fixed part of header */

		if (!encrypt_message(&md->rbody, st))
			return STF_INTERNAL_ERROR;  /* ??? we may be partly committed */

		return STF_OK;
	}
}

/*
 * Initialize RFC 3706 Dead Peer Detection
 */
static void dpd_init(struct state *st)
{
	struct state *p1st = find_state(st->st_icookie, st->st_rcookie
								, &st->st_connection->spd.that.host_addr, 0);
	
	if (p1st == NULL)
		loglog(RC_LOG_SERIOUS, "could not find phase 1 state for DPD");
	else if (p1st->st_dpd)
	{
		plog("Dead Peer Detection (RFC 3706) enabled");
		/* randomize the first DPD event */
		
		event_schedule(EVENT_DPD
			, (0.5 + rand()/(RAND_MAX + 1.E0)) * st->st_connection->dpd_delay
			, st);
	}
}

/* Handle (the single) message from Responder in Quick Mode.
 * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ] -->
 * HDR*, HASH(3)
 * (see RFC 2409 "IKE" 5.5)
 * Installs inbound and outbound IPsec SAs, routing, etc.
 */
stf_status quick_inR1_outI2(struct msg_digest *md)
{
	struct state *const st = md->st;
	const struct connection *c = st->st_connection;

	/* HASH(2) in */
	CHECK_QUICK_HASH(md
		, quick_mode_hash12(hash_val, hash_pbs->roof, md->message_pbs.roof
			, st, &st->st_msgid, TRUE)
		, "HASH(2)", "Quick R1");

	/* SA in */
	{
		struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];

		RETURN_STF_FAILURE(parse_ipsec_sa_body(&sa_pd->pbs
			, &sa_pd->payload.sa, NULL, TRUE, st));
	}

	/* Nr in */
	RETURN_STF_FAILURE(accept_nonce(md, &st->st_nr, "Nr"));

	/* [ KE ] in (for PFS) */
	RETURN_STF_FAILURE(accept_PFS_KE(md, &st->st_gr, "Gr", "Quick Mode R1"));

	if (st->st_pfs_group != NULL)
		compute_dh_shared(st, st->st_gr, st->st_pfs_group);

	/* [ IDci, IDcr ] in; these must match what we sent */

	{
		struct payload_digest *const id_pd = md->chain[ISAKMP_NEXT_ID];

		if (id_pd != NULL)
		{
			/* ??? we are assuming IPSEC_DOI */

			/* IDci (we are initiator) */

			if (!check_net_id(&id_pd->payload.ipsec_id, &id_pd->pbs
			, &st->st_myuserprotoid, &st->st_myuserport
			, &st->st_connection->spd.this.client
			, "our client"))
				return STF_FAIL + INVALID_ID_INFORMATION;

			/* IDcr (responder is peer) */

			if (!check_net_id(&id_pd->next->payload.ipsec_id, &id_pd->next->pbs
			, &st->st_peeruserprotoid, &st->st_peeruserport
			, &st->st_connection->spd.that.client
			, "peer client"))
				return STF_FAIL + INVALID_ID_INFORMATION;
		}
		else
		{
			/* no IDci, IDcr: we must check that the defaults match our proposal */
			if (!subnetisaddr(&c->spd.this.client, &c->spd.this.host_addr)
			|| !subnetisaddr(&c->spd.that.client, &c->spd.that.host_addr))
			{
				loglog(RC_LOG_SERIOUS, "IDci, IDcr payloads missing in message"
					" but default does not match proposal");
				return STF_FAIL + INVALID_ID_INFORMATION;
			}
		}
	}

	/* check the peer's group attributes */
	
	{
		const ietfAttrList_t *peer_list = NULL;
		
		get_peer_ca_and_groups(st->st_connection, &peer_list);

		if (!group_membership(peer_list, st->st_connection->name
				, st->st_connection->spd.that.groups))
		{
			char buf[BUF_LEN];

			format_groups(st->st_connection->spd.that.groups, buf, BUF_LEN);
			loglog(RC_LOG_SERIOUS, "peer is not member of one of the groups: %s"
				, buf);
			return STF_FAIL + INVALID_ID_INFORMATION;
		}
	}

		if ((st->nat_traversal & NAT_T_DETECTED)
		&&  (st->nat_traversal & NAT_T_WITH_NATOA))
		{
			nat_traversal_natoa_lookup(md);
		}

	/* ??? We used to copy the accepted proposal into the state, but it was
	 * never used.  From sa_pd->pbs.start, length pbs_room(&sa_pd->pbs).
	 */

	/**************** build reply packet HDR*, HASH(3) ****************/

	/* HDR* out done */

	/* HASH(3) out -- since this is the only content, no passes needed */
	{
		u_char  /* set by START_HASH_PAYLOAD: */
			*r_hashval, /* where in reply to jam hash value */
			*r_hash_start;      /* start of what is to be hashed */

		START_HASH_PAYLOAD(md->rbody, ISAKMP_NEXT_NONE);
		(void)quick_mode_hash3(r_hashval, st);
	}

	/* Derive new keying material */
	compute_keymats(st);

	/* Tell the kernel to establish the inbound, outbound, and routing part
	 * of the new SA (unless the commit bit is set -- which we don't support).
	 * We do this before any state updating so that
	 * failure won't look like success.
	 */
	if (!install_ipsec_sa(st, TRUE))
		return STF_INTERNAL_ERROR;

	/* encrypt message, except for fixed part of header */

	if (!encrypt_message(&md->rbody, st))
		return STF_INTERNAL_ERROR;      /* ??? we may be partly committed */

	{
	  DBG(DBG_CONTROLMORE, DBG_log("inR1_outI2: instance %s[%ld], setting newest_ipsec_sa to #%ld (was #%ld) (spd.eroute=#%ld)"
							   , st->st_connection->name
							   , st->st_connection->instance_serial
							   , st->st_serialno
							   , st->st_connection->newest_ipsec_sa
							   , st->st_connection->spd.eroute_owner));
	}
	
	st->st_connection->newest_ipsec_sa = st->st_serialno;

	/* note (presumed) success */
	if (c->gw_info != NULL)
		c->gw_info->key->last_worked_time = now();

	/* If we want DPD on this connection then initialize it */
	if (st->st_connection->dpd_action != DPD_ACTION_NONE)
		dpd_init(st);

	return STF_OK;
}

/* Handle last message of Quick Mode.
 * HDR*, HASH(3) -> done
 * (see RFC 2409 "IKE" 5.5)
 * Installs outbound IPsec SAs, routing, etc.
 */
stf_status quick_inI2(struct msg_digest *md)
{
	struct state *const st = md->st;

	/* HASH(3) in */
	CHECK_QUICK_HASH(md, quick_mode_hash3(hash_val, st)
		, "HASH(3)", "Quick I2");

	/* Tell the kernel to establish the outbound and routing part of the new SA
	 * (the previous state established inbound)
	 * (unless the commit bit is set -- which we don't support).
	 * We do this before any state updating so that
	 * failure won't look like success.
	 */
	if (!install_ipsec_sa(st, FALSE))
		return STF_INTERNAL_ERROR;

	{
	  DBG(DBG_CONTROLMORE, DBG_log("inI2: instance %s[%ld], setting newest_ipsec_sa to #%ld (was #%ld) (spd.eroute=#%ld)"
							   , st->st_connection->name
							   , st->st_connection->instance_serial
							   , st->st_serialno
							   , st->st_connection->newest_ipsec_sa
							   , st->st_connection->spd.eroute_owner));
	}

	st->st_connection->newest_ipsec_sa = st->st_serialno;

	update_iv(st);      /* not actually used, but tidy */

	/* note (presumed) success */
	{
		struct gw_info *gw = st->st_connection->gw_info;

		if (gw != NULL)
			gw->key->last_worked_time = now();
	}

	/* If we want DPD on this connection then initialize it */
	if (st->st_connection->dpd_action != DPD_ACTION_NONE)
		dpd_init(st);

	return STF_OK;
}

static stf_status send_isakmp_notification(struct state *st, u_int16_t type,
										   const void *data, size_t len)
{
	msgid_t msgid;
	pb_stream reply;
	pb_stream rbody;
	u_char
		*r_hashval,     /* where in reply to jam hash value */
		*r_hash_start;  /* start of what is to be hashed */
		
	msgid = generate_msgid(st);
	
	init_pbs(&reply, reply_buffer, sizeof(reply_buffer), "ISAKMP notify");

	/* HDR* */
	{
		struct isakmp_hdr hdr;

		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT | ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_INFO;
		hdr.isa_msgid = msgid;
		hdr.isa_flags = ISAKMP_FLAG_ENCRYPTION;
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
			impossible();
	}
	/* HASH -- create and note space to be filled later */
	START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_N);

	/* NOTIFY */
	{
		pb_stream notify_pbs;
		struct isakmp_notification isan;

		isan.isan_np = ISAKMP_NEXT_NONE;
		isan.isan_doi = ISAKMP_DOI_IPSEC;
		isan.isan_protoid = PROTO_ISAKMP;
		isan.isan_spisize = COOKIE_SIZE * 2;  
		isan.isan_type = type;
		if (!out_struct(&isan, &isakmp_notification_desc, &rbody, &notify_pbs))
			return STF_INTERNAL_ERROR;
		if (!out_raw(st->st_icookie, COOKIE_SIZE, &notify_pbs, "notify icookie"))
			return STF_INTERNAL_ERROR;  
		if (!out_raw(st->st_rcookie, COOKIE_SIZE, &notify_pbs, "notify rcookie"))
			return STF_INTERNAL_ERROR;  
		if (data != NULL && len > 0)
			if (!out_raw(data, len, &notify_pbs, "notify data"))
				return STF_INTERNAL_ERROR;    
		close_output_pbs(&notify_pbs);
	}
			
	{
		/* finish computing HASH */     
		struct hmac_ctx ctx;
		hmac_init_chunk(&ctx, st->st_oakley.hasher, st->st_skeyid_a);
		hmac_update(&ctx, (const u_char *) &msgid, sizeof(msgid_t));
		hmac_update(&ctx, r_hash_start, rbody.cur-r_hash_start);
		hmac_final(r_hashval, &ctx);  

		DBG(DBG_CRYPT,
				DBG_log("HASH computed:");
				DBG_dump("", r_hashval, ctx.hmac_digest_size));
	}

	/* Encrypt message (preserve st_iv and st_new_iv) */
	{
		u_char old_iv[MAX_DIGEST_LEN];
		u_char new_iv[MAX_DIGEST_LEN];

		u_int old_iv_len = st->st_iv_len;
		u_int new_iv_len = st->st_new_iv_len;

		if (old_iv_len > MAX_DIGEST_LEN || new_iv_len > MAX_DIGEST_LEN)
			return STF_INTERNAL_ERROR;

		memcpy(old_iv, st->st_iv, old_iv_len);
		memcpy(new_iv, st->st_new_iv, new_iv_len);

		init_phase2_iv(st, &msgid);
		if (!encrypt_message(&rbody, st))
			return STF_INTERNAL_ERROR;
	
		/* restore preserved st_iv and st_new_iv */
		memcpy(st->st_iv, old_iv, old_iv_len);
		memcpy(st->st_new_iv, new_iv, new_iv_len);
		st->st_iv_len = old_iv_len;
		st->st_new_iv_len = new_iv_len;
	}

	/* Send packet (preserve st_tpacket) */
	{
		chunk_t saved_tpacket = st->st_tpacket;

		st->st_tpacket = chunk_create(reply.start, pbs_offset(&reply));
		send_packet(st, "ISAKMP notify");
		st->st_tpacket = saved_tpacket;
	}

	return STF_IGNORE;
}

/*
 * DPD Out Initiator
 */
void dpd_outI(struct state *p2st)
{
	struct state *st;
	u_int32_t seqno;
	time_t tm;
	time_t idle_time;
	time_t delay = p2st->st_connection->dpd_delay;
	time_t timeout = p2st->st_connection->dpd_timeout;

	/* find the newest related Phase 1 state */
	st = find_phase1_state(p2st->st_connection, ISAKMP_SA_ESTABLISHED_STATES);

	if (st == NULL)
	{
		loglog(RC_LOG_SERIOUS, "DPD: Could not find newest phase 1 state");
		return;
	}

	/* If no DPD, then get out of here */
	if (!st->st_dpd)
		return;

	/* schedule the next periodic DPD event */
	event_schedule(EVENT_DPD, delay, p2st);

	/* Current time */
	tm = now();

	/* Make sure we really need to invoke DPD */
	if (!was_eroute_idle(p2st, delay, &idle_time))
	{
		DBG(DBG_CONTROL,
			DBG_log("recent eroute activity %u seconds ago, "
					"no need to send DPD notification"
				  , (int)idle_time)
		)
		st->st_last_dpd = tm;
		delete_dpd_event(st);
		return;
	}

	/* If an R_U_THERE has been sent or received recently, or if a
	 * companion Phase 2 SA has shown eroute activity,
	 * then we don't need to invoke DPD.
	 */
	if (tm < st->st_last_dpd + delay)
	{
		DBG(DBG_CONTROL,
			DBG_log("recent DPD activity %u seconds ago, "
					"no need to send DPD notification"
				  , (int)(tm - st->st_last_dpd))
		)
		return;
	}

	if (!IS_ISAKMP_SA_ESTABLISHED(st->st_state))
		return;

	if (!st->st_dpd_seqno)
	{
		rng_t *rng;

		/* Get a non-zero random value that has room to grow */
		rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
		rng->get_bytes(rng, sizeof(st->st_dpd_seqno), (u_char *)&st->st_dpd_seqno);
		rng->destroy(rng);
		st->st_dpd_seqno &= 0x7fff;
		st->st_dpd_seqno++;
	}
	seqno = htonl(st->st_dpd_seqno);

	if (send_isakmp_notification(st, R_U_THERE, &seqno, sizeof(seqno)) != STF_IGNORE)
	{
		loglog(RC_LOG_SERIOUS, "DPD: Could not send R_U_THERE");
		return;
	}
	DBG(DBG_CONTROL,
		DBG_log("sent DPD notification R_U_THERE with seqno = %u", st->st_dpd_seqno)
	)
	st->st_dpd_expectseqno = st->st_dpd_seqno++;
	st->st_last_dpd = tm;
	/* Only schedule a new timeout if there isn't one currently,
	 * or if it would be sooner than the current timeout. */
	if (st->st_dpd_event == NULL
	|| st->st_dpd_event->ev_time > tm + timeout)
	{
		delete_dpd_event(st);
		event_schedule(EVENT_DPD_TIMEOUT, timeout, st);
	}
}

/*
 * DPD in Initiator, out Responder
 */
stf_status
dpd_inI_outR(struct state *st, struct isakmp_notification *const n, pb_stream *pbs)
{
   time_t tm = now();
	u_int32_t seqno;

	if (st == NULL || !IS_ISAKMP_SA_ESTABLISHED(st->st_state))
	{
		loglog(RC_LOG_SERIOUS, "DPD: Received R_U_THERE for unestablished ISAKMP SA");
		return STF_IGNORE;
	}
	if (n->isan_spisize != COOKIE_SIZE * 2 || pbs_left(pbs) < COOKIE_SIZE * 2)
	{
		loglog(RC_LOG_SERIOUS, "DPD: R_U_THERE has invalid SPI length (%d)", n->isan_spisize);
		return STF_FAIL + PAYLOAD_MALFORMED;
	}

	if (memcmp(pbs->cur, st->st_icookie, COOKIE_SIZE) != 0)
	{
#ifdef APPLY_CRISCO
		/* Ignore it, cisco sends odd icookies */
#else
		loglog(RC_LOG_SERIOUS, "DPD: R_U_THERE has invalid icookie (broken Cisco?)");
		return STF_FAIL + INVALID_COOKIE;
#endif
	}
	pbs->cur += COOKIE_SIZE;

	if (memcmp(pbs->cur, st->st_rcookie, COOKIE_SIZE) != 0)
	{
		loglog(RC_LOG_SERIOUS, "DPD: R_U_THERE has invalid rcookie (broken Cisco?)");
		return STF_FAIL + INVALID_COOKIE;
	}
	pbs->cur += COOKIE_SIZE;

	if (pbs_left(pbs) != sizeof(seqno))
	{
		loglog(RC_LOG_SERIOUS, "DPD: R_U_THERE has invalid data length (%d)"
			, (int) pbs_left(pbs));
		return STF_FAIL + PAYLOAD_MALFORMED;
	}

	seqno = ntohl(*(u_int32_t *)pbs->cur);
	DBG(DBG_CONTROL,
		DBG_log("received DPD notification R_U_THERE with seqno = %u", seqno)
	)

	if (st->st_dpd_peerseqno && seqno <= st->st_dpd_peerseqno) {
		loglog(RC_LOG_SERIOUS, "DPD: Received old or duplicate R_U_THERE");
		return STF_IGNORE;
	}

	st->st_dpd_peerseqno = seqno;
	delete_dpd_event(st);

	if (send_isakmp_notification(st, R_U_THERE_ACK, pbs->cur, pbs_left(pbs)) != STF_IGNORE)
	{
		loglog(RC_LOG_SERIOUS, "DPD Info: could not send R_U_THERE_ACK");
		return STF_IGNORE;
	}
	DBG(DBG_CONTROL,
		DBG_log("sent DPD notification R_U_THERE_ACK with seqno = %u", seqno)
	)

	st->st_last_dpd = tm;
	return STF_IGNORE;
}

/*
 * DPD out Responder
 */
stf_status dpd_inR(struct state *st, struct isakmp_notification *const n,
				   pb_stream *pbs)
{
	u_int32_t seqno;

	if (st == NULL || !IS_ISAKMP_SA_ESTABLISHED(st->st_state))
	{
		loglog(RC_LOG_SERIOUS
			, "DPD: Received R_U_THERE_ACK for unestablished ISAKMP SA");
		return STF_FAIL;
	}

   if (n->isan_spisize != COOKIE_SIZE * 2 || pbs_left(pbs) < COOKIE_SIZE * 2)
	{
		loglog(RC_LOG_SERIOUS
			, "DPD: R_U_THERE_ACK has invalid SPI length (%d)"
			, n->isan_spisize);
		return STF_FAIL + PAYLOAD_MALFORMED;
	}

	if (memcmp(pbs->cur, st->st_icookie, COOKIE_SIZE) != 0)
	{
#ifdef APPLY_CRISCO
		/* Ignore it, cisco sends odd icookies */
#else
		loglog(RC_LOG_SERIOUS, "DPD: R_U_THERE_ACK has invalid icookie");
		return STF_FAIL + INVALID_COOKIE;
#endif
	}
	pbs->cur += COOKIE_SIZE;

	if (memcmp(pbs->cur, st->st_rcookie, COOKIE_SIZE) != 0)
	{
#ifdef APPLY_CRISCO
		/* Ignore it, cisco sends odd icookies */
#else
		loglog(RC_LOG_SERIOUS, "DPD: R_U_THERE_ACK has invalid rcookie");
		return STF_FAIL + INVALID_COOKIE;
#endif
	}
	pbs->cur += COOKIE_SIZE;

	if (pbs_left(pbs) != sizeof(seqno))
	{
		loglog(RC_LOG_SERIOUS
			, " DPD: R_U_THERE_ACK has invalid data length (%d)"
			, (int) pbs_left(pbs));
		return STF_FAIL + PAYLOAD_MALFORMED;
	}

	seqno = ntohl(*(u_int32_t *)pbs->cur);
	DBG(DBG_CONTROL,
		DBG_log("received DPD notification R_U_THERE_ACK with seqno = %u"
		, seqno)
	)

	if (!st->st_dpd_expectseqno && seqno != st->st_dpd_expectseqno)
	{
		loglog(RC_LOG_SERIOUS
			, "DPD: R_U_THERE_ACK has unexpected sequence number");
		return STF_FAIL + PAYLOAD_MALFORMED;
	}

	st->st_dpd_expectseqno = 0;
	delete_dpd_event(st);
	return STF_IGNORE;
}

/*
 * DPD Timeout Function
 *
 * This function is called when a timeout DPD_EVENT occurs.  We set clear/trap
 * both the SA and the eroutes, depending on what the connection definition
 * tells us (either 'hold' or 'clear')
 */
void
dpd_timeout(struct state *st)
{
	struct state *newest_phase1_st;
	struct connection *c = st->st_connection;
	int action = st->st_connection->dpd_action;
	char cname[BUF_LEN];

	passert(action == DPD_ACTION_HOLD
		 || action == DPD_ACTION_CLEAR
		 || DPD_ACTION_RESTART);

	/* is there a newer phase1_state? */
	newest_phase1_st = find_phase1_state(c, ISAKMP_SA_ESTABLISHED_STATES);
	if (newest_phase1_st != NULL && newest_phase1_st != st)
	{
		plog("DPD: Phase1 state #%ld has been superseded by #%ld"
			 " - timeout ignored"
			 , st->st_serialno, newest_phase1_st->st_serialno);
		return;
	}

	loglog(RC_LOG_SERIOUS, "DPD: No response from peer - declaring peer dead");

	/* delete the state, which is probably in phase 2 */
	set_cur_connection(c);
	plog("DPD: Terminating all SAs using this connection");
	delete_states_by_connection(c, TRUE);
	reset_cur_connection();

	switch (action)
	{
	case DPD_ACTION_HOLD:
		/* dpdaction=hold - Wipe the SA's but %trap the eroute so we don't
		 * leak traffic.  Also, being in %trap means new packets will
		 * force an initiation of the conn again.
		 */
		loglog(RC_LOG_SERIOUS, "DPD: Putting connection \"%s\" into %%trap", c->name);
		if (c->kind == CK_INSTANCE)
			delete_connection(c, TRUE);
		break;
	case DPD_ACTION_CLEAR:
		/* dpdaction=clear - Wipe the SA & eroute - everything */
		loglog(RC_LOG_SERIOUS, "DPD: Clearing connection \"%s\"", c->name);
		unroute_connection(c);
		if (c->kind == CK_INSTANCE)
			delete_connection(c, TRUE);
		break;
	case DPD_ACTION_RESTART:
		/* dpdaction=restart - Restart connection,
		 * except if roadwarrior connection
		 */
		loglog(RC_LOG_SERIOUS, "DPD: Restarting connection \"%s\"", c->name);
		unroute_connection(c);

		/* caching the connection name before deletion */
		strncpy(cname, c->name, BUF_LEN);

		if (c->kind == CK_INSTANCE)
			delete_connection(c, TRUE);
		initiate_connection(cname, NULL_FD);
		break;
	default:
		loglog(RC_LOG_SERIOUS, "DPD: unknown action");
	}
}

