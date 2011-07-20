/* Security Policy Data Base (such as it is)
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier.
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

#ifndef _SPDB_H
#define _SPDB_H

#include "packet.h"

/* database of SA properties */

/* Attribute type and value pair.
 * Note: only "basic" values are represented so far.
 */
struct db_attr {
	u_int16_t type;     /* ISAKMP_ATTR_AF_TV is implied; 0 for end */
	u_int16_t val;
};

/* transform */
struct db_trans {
	u_int8_t transid;   /* Transform-Id */
	struct db_attr *attrs;      /* array */
	int attr_cnt;       /* number of elements */
};

/* proposal */
struct db_prop {
	u_int8_t protoid;   /* Protocol-Id */
	struct db_trans *trans;     /* array (disjunction) */
	int trans_cnt;      /* number of elements */
	/* SPI size and value isn't part of DB */
};

/* conjunction of proposals */
struct db_prop_conj {
	struct db_prop *props;      /* array */
	int prop_cnt;       /* number of elements */
};

/* security association */
struct db_sa {
	struct db_prop_conj *prop_conjs;    /* array */
	int prop_conj_cnt;  /* number of elements */
	/* Hardwired for now;
	 * DOI: ISAKMP_DOI_IPSEC
	 * Situation: SIT_IDENTITY_ONLY
	 */
};

/* The oakley sadb */
extern struct db_sa oakley_sadb;

/* The ipsec sadb is subscripted by a bitset with members
 * from POLICY_ENCRYPT, POLICY_AUTHENTICATE, POLICY_COMPRESS
 */
extern struct db_sa ipsec_sadb[1 << 3];

/* forward declaration */
struct state;

extern bool out_sa(
	pb_stream *outs,
	struct db_sa *sadb,
	struct state *st,
	bool oakley_mode,
	u_int8_t np);

extern notification_t preparse_isakmp_sa_body(
	const struct isakmp_sa *sa, /* header of input SA Payload */
	pb_stream *sa_pbs,          /* body of input SA Payload */
	u_int32_t *ipsecdoisit,     /* IPsec DOI SIT bitset */
	pb_stream *proposal_pbs,    /* body of proposal Payload */
	struct isakmp_proposal *proposal);

extern notification_t parse_isakmp_policy(
	pb_stream *proposal_pbs,    /* body of proposal Payload */
	u_int notrans,              /* number of transforms */
	lset_t *policy);            /* RSA, PSK or XAUTH policy */

extern notification_t parse_isakmp_sa_body(
	u_int32_t ipsecdoisit,      /* IPsec DOI SIT bitset */
	pb_stream *proposal_pbs,    /* body of proposal Payload */
	struct isakmp_proposal *proposal,
	pb_stream *r_sa_pbs,        /* if non-NULL, where to emit winning SA */
	struct state *st,           /* current state object */
	bool initiator);            /* is caller initiator? */

extern notification_t parse_ipsec_sa_body(
	pb_stream *sa_pbs,          /* body of input SA Payload */
	const struct isakmp_sa *sa, /* header of input SA Payload */
	pb_stream *r_sa_pbs,        /* if non-NULL, where to emit winning SA */
	bool selection,             /* if this SA is a selection, only one transform can appear */
	struct state *st);          /* current state object */

extern void backup_pbs(pb_stream *pbs);
extern void restore_pbs(pb_stream *pbs);

#endif /* _SPDB_H */

