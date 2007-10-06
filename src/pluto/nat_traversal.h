/* FreeS/WAN NAT-Traversal
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
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
 * RCSID $Id$
 */

#ifndef _NAT_TRAVERSAL_H
#define _NAT_TRAVERSAL_H

#include "packet.h"

#define NAT_TRAVERSAL_IETF_00_01     1
#define NAT_TRAVERSAL_IETF_02_03     2
#define NAT_TRAVERSAL_RFC            3

#define NAT_TRAVERSAL_NAT_BHND_ME    30
#define NAT_TRAVERSAL_NAT_BHND_PEER  31

#define NAT_TRAVERSAL_METHOD  (0xffffffff - LELEM(30) - LELEM(31))

/**
 * NAT-Traversal methods which need NAT-D
 */
#define NAT_T_WITH_NATD \
	( LELEM(NAT_TRAVERSAL_IETF_00_01) | LELEM(NAT_TRAVERSAL_IETF_02_03) | \
	LELEM(NAT_TRAVERSAL_RFC) )
/**
 * NAT-Traversal methods which need NAT-OA
 */
#define NAT_T_WITH_NATOA \
	( LELEM(NAT_TRAVERSAL_IETF_00_01) | LELEM(NAT_TRAVERSAL_IETF_02_03) | \
	LELEM(NAT_TRAVERSAL_RFC) )
/**
 * NAT-Traversal methods which use NAT-KeepAlive
 */
#define NAT_T_WITH_KA \
	( LELEM(NAT_TRAVERSAL_IETF_00_01) | LELEM(NAT_TRAVERSAL_IETF_02_03) | \
	LELEM(NAT_TRAVERSAL_RFC) )
/**
 * NAT-Traversal methods which use floating port
 */
#define NAT_T_WITH_PORT_FLOATING \
	( LELEM(NAT_TRAVERSAL_IETF_02_03) | LELEM(NAT_TRAVERSAL_RFC) )

/**
 * NAT-Traversal methods which use officials values (RFC)
 */
#define NAT_T_WITH_RFC_VALUES \
	( LELEM(NAT_TRAVERSAL_RFC) )

/**
 * NAT-Traversal detected
 */
#define NAT_T_DETECTED \
	( LELEM(NAT_TRAVERSAL_NAT_BHND_ME) | LELEM(NAT_TRAVERSAL_NAT_BHND_PEER) )

/**
 * NAT-T Port Floating
 */
#define NAT_T_IKE_FLOAT_PORT     4500

void init_nat_traversal (bool activate, unsigned int keep_alive_period,
	bool fka, bool spf);

extern bool nat_traversal_enabled;
extern bool nat_traversal_support_non_ike;
extern bool nat_traversal_support_port_floating;

/**
 * NAT-D
 */
void nat_traversal_natd_lookup(struct msg_digest *md);
#ifndef PB_STREAM_UNDEFINED
bool nat_traversal_add_natd(u_int8_t np, pb_stream *outs,
	struct msg_digest *md);
#endif

/**
 * NAT-OA
 */
void nat_traversal_natoa_lookup(struct msg_digest *md);
#ifndef PB_STREAM_UNDEFINED
bool nat_traversal_add_natoa(u_int8_t np, pb_stream *outs,
	struct state *st);
#endif

/**
 * NAT-keep_alive
 */
void nat_traversal_new_ka_event (void);
void nat_traversal_ka_event (void);

void nat_traversal_show_result (u_int32_t nt, u_int16_t sport);

int nat_traversal_espinudp_socket (int sk, u_int32_t type);

/**
 * Vendor ID
 */
#ifndef PB_STREAM_UNDEFINED
bool nat_traversal_add_vid(u_int8_t np, pb_stream *outs);
#endif
u_int32_t nat_traversal_vid_to_method(unsigned short nat_t_vid);

void nat_traversal_change_port_lookup(struct msg_digest *md, struct state *st);

/**
 * New NAT mapping
 */
#ifdef __PFKEY_V2_H
void process_pfkey_nat_t_new_mapping(
	struct sadb_msg *,
	struct sadb_ext *[SADB_EXT_MAX + 1]);
#endif

/**
 * IKE port floating
 */
bool
nat_traversal_port_float(struct state *st, struct msg_digest *md, bool in);

/**
 * Encapsulation mode macro (see demux.c)
 */
#define NAT_T_ENCAPSULATION_MODE(st,nat_t_policy) ( \
	((st)->nat_traversal & NAT_T_DETECTED) \
		? ( ((nat_t_policy) & POLICY_TUNNEL) \
			? ( ((st)->nat_traversal & NAT_T_WITH_RFC_VALUES) \
				? (ENCAPSULATION_MODE_UDP_TUNNEL_RFC) \
				: (ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS) \
			  ) \
			: ( ((st)->nat_traversal & NAT_T_WITH_RFC_VALUES) \
				? (ENCAPSULATION_MODE_UDP_TRANSPORT_RFC) \
				: (ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS) \
			  ) \
		  ) \
		: ( ((st)->st_policy & POLICY_TUNNEL) \
			? (ENCAPSULATION_MODE_TUNNEL) \
			: (ENCAPSULATION_MODE_TRANSPORT) \
		  ) \
	)

#endif /* _NAT_TRAVERSAL_H */

