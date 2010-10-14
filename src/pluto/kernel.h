/* declarations of routines that interface with the kernel's IPsec mechanism
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
 */

#include "connections.h"

extern bool can_do_IPcomp;  /* can system actually perform IPCOMP? */

/* Declare eroute things early enough for uses.
 *
 * Flags are encoded above the low-order byte of verbs.
 * "real" eroutes are only outbound.  Inbound eroutes don't exist,
 * but an addflow with an INBOUND flag allows IPIP tunnels to be
 * limited to appropriate source and destination addresses.
 */

#define ERO_MASK        0xFF
#define ERO_FLAG_SHIFT  8

#define ERO_DELETE      SADB_X_DELFLOW
#define ERO_ADD SADB_X_ADDFLOW
#define ERO_REPLACE     (SADB_X_ADDFLOW | (SADB_X_SAFLAGS_REPLACEFLOW << ERO_FLAG_SHIFT))

struct pfkey_proto_info {
		int proto;
		int encapsulation;
		unsigned reqid;
};
struct sadb_msg;

struct kernel_sa {
		const ip_address *src;
		const ip_address *dst;

		const ip_subnet *src_client;
		const ip_subnet *dst_client;

		ipsec_spi_t spi;
		unsigned proto;
		unsigned satype;
		unsigned transport_proto;
		unsigned replay_window;
		unsigned reqid;

		unsigned authalg;
		unsigned authkeylen;
		char *authkey;

		unsigned encalg;
		unsigned enckeylen;
		char *enckey;

		unsigned compalg;

		int encapsulation;

		u_int16_t natt_sport, natt_dport;
		u_int8_t transid, natt_type;
		ip_address *natt_oa;

		const char *text_said;
};

/* A netlink header defines EM_MAXRELSPIS, the max number of SAs in a group.
 * Is there a PF_KEY equivalent?
 */
#ifndef EM_MAXRELSPIS
# define EM_MAXRELSPIS 4        /* AH ESP IPCOMP IPIP */
#endif

extern void record_and_initiate_opportunistic(const ip_subnet *
											  , const ip_subnet *
											  , int transport_proto
											  , const char *why);

extern void init_kernel(void);
extern void kernel_finalize(void);

extern bool trap_connection(struct connection *c);
extern void unroute_connection(struct connection *c);

extern bool assign_hold(struct connection *c
						, struct spd_route *sr
						, int transport_proto
						, const ip_address *src, const ip_address *dst);

extern ipsec_spi_t shunt_policy_spi(struct connection *c, bool prospective);


struct state;   /* forward declaration of tag */
extern ipsec_spi_t get_ipsec_spi(ipsec_spi_t avoid
								 , int proto
								 , struct spd_route *sr
								 , bool tunnel_mode);
extern ipsec_spi_t get_my_cpi(struct spd_route *sr, bool tunnel_mode);

extern bool install_inbound_ipsec_sa(struct state *st);
extern bool install_ipsec_sa(struct state *st, bool inbound_also);
extern void delete_ipsec_sa(struct state *st, bool inbound_only);
extern bool route_and_eroute(struct connection *c
							 , struct spd_route *sr
							 , struct state *st);
extern bool was_eroute_idle(struct state *st, time_t idle_max
	, time_t *idle_time);
extern bool get_sa_info(struct state *st, bool inbound, u_int *bytes
	, time_t *use_time);

extern bool update_ipsec_sa(struct state *st);
