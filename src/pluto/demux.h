/* demultiplex incoming IKE messages
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

#include "packet.h"

struct state;   /* forward declaration of tag */
extern void init_demux(void);
extern bool send_packet(struct state *st, const char *where);
extern void comm_handle(const struct iface *ifp);

extern u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];

/* State transition function infrastructure
 *
 * com_handle parses a message, decides what state object it applies to,
 * and calls the appropriate state transition function (STF).
 * These declarations define the interface to these functions.
 *
 * Each STF must be able to be restarted up to any failure point:
 * a later message will cause the state to be re-entered.  This
 * explains the use of the replace macro and the care in handling
 * MP_INT members of struct state.
 */

struct payload_digest {
	pb_stream pbs;
	union payload payload;
	struct payload_digest *next;   /* of same kind */
};

/* message digest
 * Note: raw_packet and packet_pbs are "owners" of space on heap.
 */

struct msg_digest {
	struct msg_digest *next;    /* for free list */
	chunk_t raw_packet;         /* if encrypted, received packet before decryption */
	const struct iface *iface;  /* interface on which message arrived */
	ip_address sender;  /* where message came from */
	u_int16_t sender_port;      /* host order */
	pb_stream packet_pbs;       /* whole packet */
	pb_stream message_pbs;      /* message to be processed */
	struct isakmp_hdr hdr;      /* message's header */
	bool encrypted;             /* was it encrypted? */
	enum state_kind from_state; /* state we started in */
	const struct state_microcode *smc;  /* microcode for initial state */
	struct state *st;           /* current state object */
	pb_stream reply;            /* room for reply */
	pb_stream rbody;            /* room for reply body (after header) */
	notification_t note;        /* reason for failure */
	bool dpd;                   /* peer supports RFC 3706 DPD */
	bool openpgp;               /* peer supports OpenPGP certificates */

#   define PAYLIMIT 40
	struct payload_digest
		digest[PAYLIMIT],
		*digest_roof,
		*chain[ISAKMP_NEXT_ROOF];
		unsigned short nat_traversal_vid;
};

extern void release_md(struct msg_digest *md);

/* status for state-transition-function
 * Note: STF_FAIL + notification_t means fail with that notification
 */

typedef enum {
	STF_IGNORE, /* don't respond */
	STF_SUSPEND,    /* unfinished -- don't release resources */
	STF_OK,     /* success */
	STF_INTERNAL_ERROR, /* discard everything, we failed */
	STF_FAIL    /* discard everything, something failed.  notification_t added. */
} stf_status;

typedef stf_status state_transition_fn(struct msg_digest *md);

extern void complete_state_transition(struct msg_digest **mdp, stf_status result);

extern void free_md_pool(void);
