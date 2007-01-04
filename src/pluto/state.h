/* state and event objects
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
 *
 * RCSID $Id: state.h,v 1.11 2006/03/08 22:12:37 as Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <gmp.h>    /* GNU MP library */

#include "connections.h"

/* Message ID mechanism.
 *
 * A Message ID is contained in each IKE message header.
 * For Phase 1 exchanges (Main and Aggressive), it will be zero.
 * For other exchanges, which must be under the protection of an
 * ISAKMP SA, the Message ID must be unique within that ISAKMP SA.
 * Effectively, this labels the message as belonging to a particular
 * exchange.
 *
 * RFC2408 "ISAKMP" 3.1 "ISAKMP Header Format" (near end) states that
 * the Message ID must be unique.  We interpret this to be "unique within
 * one ISAKMP SA".
 *
 * BTW, we feel this uniqueness allows rekeying to be somewhat simpler
 * than specified by draft-jenkins-ipsec-rekeying-06.txt.
 */

typedef u_int32_t msgid_t;	/* Network order! */
#define MAINMODE_MSGID    ((msgid_t) 0)

struct state;	/* forward declaration of tag */
extern bool reserve_msgid(struct state *isakmp_sa, msgid_t msgid);
extern msgid_t generate_msgid(struct state *isakmp_sa);


/* Oakley (Phase 1 / Main Mode) transform and attributes
 * This is a flattened/decoded version of what is represented
 * in the Transaction Payload.
 * Names are chosen to match corresponding names in state.
 */
struct oakley_trans_attrs {
    u_int16_t encrypt;		/* Encryption algorithm */
    u_int16_t enckeylen;	/* encryption key len (bits) */
    const struct encrypt_desc *encrypter;	/* package of encryption routines */
    u_int16_t hash;		/* Hash algorithm */
    const struct hash_desc *hasher;	/* package of hashing routines */
    u_int16_t auth;		/* Authentication method */
    const struct oakley_group_desc *group;	/* Oakley group */
    time_t life_seconds;	/* When this SA expires (seconds) */
    u_int32_t life_kilobytes;	/* When this SA is exhausted (kilobytes) */
#if 0 /* not yet */
    u_int16_t prf;		/* Pseudo Random Function */
#endif
};

/* IPsec (Phase 2 / Quick Mode) transform and attributes
 * This is a flattened/decoded version of what is represented
 * by a Transaction Payload.  There may be one for AH, one
 * for ESP, and a funny one for IPCOMP.
 */
struct ipsec_trans_attrs {
    u_int8_t transid;	/* transform id */
    ipsec_spi_t spi;	/* his SPI */
    time_t life_seconds;		/* When this SA expires */
    u_int32_t life_kilobytes;	/* When this SA expires */
    u_int16_t encapsulation;
    u_int16_t auth;
    u_int16_t key_len;
    u_int16_t key_rounds;
#if 0 /* not implemented yet */
    u_int16_t cmprs_dict_sz;
    u_int32_t cmprs_alg;
#endif
};

/* IPsec per protocol state information */
struct ipsec_proto_info {
    bool present;	/* was this transform specified? */
    struct ipsec_trans_attrs attrs;
    ipsec_spi_t our_spi;
    u_int16_t keymat_len;	/* same for both */
    u_char *our_keymat;
    u_char *peer_keymat;
};

/* state object: record the state of a (possibly nascent) SA
 *
 * Invariants (violated only during short transitions):
 * - each state object will be in statetable exactly once.
 * - each state object will always have a pending event.
 *   This prevents leaks.
 */
struct state
{
    so_serial_t        st_serialno;            /* serial number (for seniority) */
    so_serial_t        st_clonedfrom;          /* serial number of parent */

    struct connection *st_connection;          /* connection for this SA */

    int                st_whack_sock;          /* fd for our Whack TCP socket.
                                                * Single copy: close when freeing struct.
                                                */

    struct msg_digest *st_suspended_md;        /* suspended state-transition */

    struct oakley_trans_attrs st_oakley;

    struct ipsec_proto_info st_ah;
    struct ipsec_proto_info st_esp;
    struct ipsec_proto_info st_ipcomp;
#ifdef KLIPS
    ipsec_spi_t        st_tunnel_in_spi;          /* KLUDGE */
    ipsec_spi_t        st_tunnel_out_spi;         /* KLUDGE */
#endif

    const struct oakley_group_desc *st_pfs_group;	/* group for Phase 2 PFS */

    u_int32_t          st_doi;                 /* Domain of Interpretation */
    u_int32_t          st_situation;

    lset_t             st_policy;              /* policy for IPsec SA */

    msgid_t            st_msgid;               /* MSG-ID from header.  Network Order! */

    /* only for a state representing an ISAKMP SA */
    struct msgid_list  *st_used_msgids;        /* used-up msgids */

/* symmetric stuff */

  /* initiator stuff */
    chunk_t            st_gi;                  /* Initiator public value */
    u_int8_t           st_icookie[COOKIE_SIZE];/* Initiator Cookie */
    chunk_t            st_ni;                  /* Ni nonce */

  /* responder stuff */
    chunk_t            st_gr;                  /* Responder public value */
    u_int8_t           st_rcookie[COOKIE_SIZE];/* Responder Cookie */
    chunk_t            st_nr;                  /* Nr nonce */


  /* my stuff */

    chunk_t            st_tpacket;             /* Transmitted packet */

    /* Phase 2 ID payload info about my user */
    u_int8_t           st_myuserprotoid;       /* IDcx.protoid */
    u_int16_t          st_myuserport;

  /* his stuff */

    chunk_t            st_rpacket;             /* Received packet */

    /* Phase 2 ID payload info about peer's user */
    u_int8_t           st_peeruserprotoid;     /* IDcx.protoid */
    u_int16_t          st_peeruserport;

/* end of symmetric stuff */

    u_int8_t           st_sec_in_use;          /* bool: does st_sec hold a value */
    MP_INT             st_sec;                 /* Our local secret value */

    chunk_t            st_shared;              /* Derived shared secret
                                                * Note: during Quick Mode,
                                                * presence indicates PFS
                                                * selected.
                                                */

    /* In a Phase 1 state, preserve peer's public key after authentication */
    struct pubkey     *st_peer_pubkey;

    enum state_kind    st_state;               /* State of exchange */
    u_int8_t           st_retransmit;          /* Number of retransmits */
    unsigned long      st_try;                 /* number of times rekeying attempted */
                                               /* 0 means the only time */
    time_t             st_margin;              /* life after EVENT_SA_REPLACE */
    unsigned long      st_outbound_count;      /* traffic through eroute */
    time_t             st_outbound_time;       /* time of last change to st_outbound_count */
    chunk_t            st_p1isa;               /* Phase 1 initiator SA (Payload) for HASH */
    chunk_t            st_skeyid;              /* Key material */
    chunk_t            st_skeyid_d;            /* KM for non-ISAKMP key derivation */
    chunk_t            st_skeyid_a;            /* KM for ISAKMP authentication */
    chunk_t            st_skeyid_e;            /* KM for ISAKMP encryption */
    u_char             st_iv[MAX_DIGEST_LEN];  /* IV for encryption */
    u_char             st_new_iv[MAX_DIGEST_LEN];
    u_char             st_ph1_iv[MAX_DIGEST_LEN]; /* IV at end if phase 1 */
    unsigned int       st_iv_len;
    unsigned int       st_new_iv_len;
    unsigned int       st_ph1_iv_len;

    chunk_t            st_enc_key;             /* Oakley Encryption key */

    struct event      *st_event;               /* backpointer for certain events */
    struct state      *st_hashchain_next;      /* Next in list */
    struct state      *st_hashchain_prev;      /* Previous in list */

    struct {
	bool vars_set;
	bool started;
    } st_modecfg;

    struct {
	int attempt;
	bool started;
	bool status;
    } st_xauth;

    u_int32_t         nat_traversal;
    ip_address        nat_oa;

    /* RFC 3706 Dead Peer Detection */
    bool                st_dpd;			/* Peer supports DPD */
    time_t              st_last_dpd;		/* Time of last DPD transmit */
    u_int32_t           st_dpd_seqno;		/* Next R_U_THERE to send */
    u_int32_t           st_dpd_expectseqno;	/* Next R_U_THERE_ACK to receive */
    u_int32_t           st_dpd_peerseqno;	/* global variables */
    struct event        *st_dpd_event;		/* backpointer for DPD events */

    u_int32_t	      st_seen_vendorid;		/* Bit field about recognized Vendor ID */
};

/* global variables */

extern u_int16_t pluto_port;	/* Pluto's port */

extern bool states_use_connection(struct connection *c);

/* state functions */

extern struct state *new_state(void);
extern void init_states(void);
extern void insert_state(struct state *st);
extern void unhash_state(struct state *st);
extern void release_whack(struct state *st);
extern void state_eroute_usage(ip_subnet *ours, ip_subnet *his
    , unsigned long count, time_t nw);
extern void delete_state(struct state *st);
extern void delete_states_by_connection(struct connection *c, bool relations);

extern struct state
    *duplicate_state(struct state *st),
    *find_state(const u_char *icookie
	, const u_char *rcookie
	, const ip_address *peer
	, msgid_t msgid),
    *state_with_serialno(so_serial_t sn),
    *find_phase2_state_to_delete(const struct state *p1st, u_int8_t protoid
	, ipsec_spi_t spi, bool *bogus),
    *find_phase1_state(const struct connection *c, lset_t ok_states),
    *find_sender(size_t packet_len, u_char *packet);

extern void show_states_status(bool all, const char *name);
extern void for_each_state(void *(f)(struct state *, void *data), void *data);
extern void find_my_cpi_gap(cpi_t *latest_cpi, cpi_t *first_busy_cpi);
extern ipsec_spi_t uniquify_his_cpi(ipsec_spi_t cpi, struct state *st);
extern void fmt_state(bool all, struct state *st, time_t n
		     , char *state_buf, size_t state_buf_len
		     , char *state_buf2, size_t state_buf_len2);
extern void delete_states_by_peer(ip_address *peer);
