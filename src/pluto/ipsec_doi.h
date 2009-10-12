/* IPsec DOI and Oakley resolution routines
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

#ifndef _IPSEC_DOI_H
#define _IPSEC_DOI_H

#include "defs.h"

extern void echo_hdr(struct msg_digest *md, bool enc, u_int8_t np);

extern void ipsecdoi_initiate(int whack_sock, struct connection *c
	, lset_t policy, unsigned long try, so_serial_t replacing);

extern void ipsecdoi_replace(struct state *st, unsigned long try);

extern void init_phase2_iv(struct state *st, const msgid_t *msgid);

extern stf_status quick_outI1(int whack_sock
	, struct state *isakmp_sa
	, struct connection *c
	, lset_t policy
	, unsigned long try
	, so_serial_t replacing);

extern state_transition_fn
	main_inI1_outR1,
	main_inR1_outI2,
	main_inI2_outR2,
	main_inR2_outI3,
	main_inI3_outR3,
	main_inR3,
	quick_inI1_outR1,
	quick_inR1_outI2,
	quick_inI2;

extern void send_delete(struct state *st);
extern void accept_delete(struct state *st, struct msg_digest *md
	, struct payload_digest *p);
extern void close_message(pb_stream *pbs);
extern bool encrypt_message(pb_stream *pbs, struct state *st);


extern void send_notification_from_state(struct state *st,
	enum state_kind state, u_int16_t type);
extern void send_notification_from_md(struct msg_digest *md, u_int16_t type);

extern const char *init_pluto_vendorid(void);

extern void dpd_outI(struct state *st);
extern stf_status dpd_inI_outR(struct state *st
			, struct isakmp_notification *const n, pb_stream *n_pbs);
extern stf_status dpd_inR(struct state *st
			, struct isakmp_notification *const n, pb_stream *n_pbs);
extern void dpd_timeout(struct state *st);

/* START_HASH_PAYLOAD
 *
 * Emit a to-be-filled-in hash payload, noting the field start (r_hashval)
 * and the start of the part of the message to be hashed (r_hash_start).
 * This macro is magic.
 * - it can cause the caller to return
 * - it references variables local to the caller (r_hashval, r_hash_start, st)
 */
#define START_HASH_PAYLOAD(rbody, np) { \
	pb_stream hash_pbs; \
	if (!out_generic(np, &isakmp_hash_desc, &(rbody), &hash_pbs)) \
		return STF_INTERNAL_ERROR; \
	r_hashval = hash_pbs.cur;   /* remember where to plant value */ \
	if (!out_zero(st->st_oakley.hasher->hash_digest_size, &hash_pbs, "HASH")) \
		return STF_INTERNAL_ERROR; \
	close_output_pbs(&hash_pbs); \
	r_hash_start = (rbody).cur; /* hash from after HASH payload */ \
}

/* CHECK_QUICK_HASH
 *
 * This macro is magic -- it cannot be expressed as a function.
 * - it causes the caller to return!
 * - it declares local variables and expects the "do_hash" argument
 *   expression to reference them (hash_val, hash_pbs)
 */
#define CHECK_QUICK_HASH(md, do_hash, hash_name, msg_name) { \
		pb_stream *const hash_pbs = &md->chain[ISAKMP_NEXT_HASH]->pbs; \
		u_char hash_val[MAX_DIGEST_LEN]; \
		size_t hash_len = do_hash; \
		if (pbs_left(hash_pbs) != hash_len \
		|| memcmp(hash_pbs->cur, hash_val, hash_len) != 0) \
		{ \
			DBG_cond_dump(DBG_CRYPT, "received " hash_name ":", hash_pbs->cur, pbs_left(hash_pbs)); \
			loglog(RC_LOG_SERIOUS, "received " hash_name " does not match computed value in " msg_name); \
			/* XXX Could send notification back */ \
			return STF_FAIL + ISAKMP_INVALID_HASH_INFORMATION; \
		} \
	}

#endif /* _IPSEC_DOI_H */

