/* information about connections between hosts and clients
 * Copyright (C) 1998-2001  D. Hugh Redelmeier
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

#ifndef _CONNECTIONS_H
#define _CONNECTIONS_H

#include <sys/queue.h>

#include "id.h"
#include "certs.h"
#include "ac.h"
#include "smartcard.h"
#include "whack.h"

/* There are two kinds of connections:
 * - ISAKMP connections, between hosts (for IKE communication)
 * - IPsec connections, between clients (for secure IP communication)
 *
 * An ISAKMP connection looks like:
 *   host<--->host
 *
 * An IPsec connection looks like:
 *   client-subnet<-->host<->nexthop<--->nexthop<->host<-->client-subnet
 *
 * For the connection to be relevant to this instance of Pluto,
 * exactly one of the hosts must be a public interface of our machine
 * known to this instance.
 *
 * The client subnet might simply be the host -- this is a
 * representation of "host mode".
 *
 * Each nexthop defaults to the neighbouring host's IP address.
 * The nexthop is a property of the pair of hosts, not each
 * individually.  It is only needed for IPsec because of the
 * way IPsec is mixed into the kernel routing logic.  Furthermore,
 * only this end's nexthop is actually used.  Eventually, nexthop
 * will be unnecessary.
 *
 * Other information represented:
 * - each connection has a name: a chunk of uninterpreted text
 *   that is unique for each connection.
 * - security requirements (currently just the "policy" flags from
 *   the whack command to initiate the connection, but eventually
 *   much more.  Different for ISAKMP and IPsec connections.
 * - rekeying parameters:
 *   + time an SA may live
 *   + time before SA death that a rekeying should be attempted
 *     (only by the initiator)
 *   + number of times to attempt rekeying
 * - With the current KLIPS, we must route packets for a client
 *   subnet through the ipsec interface (ipsec0).  Only one
 *   gateway can get traffic for a specific (client) subnet.
 *   Furthermore, if the routing isn't in place, packets will
 *   be sent in the clear.
 *   "routing" indicates whether the routing has been done for
 *   this connection.  Note that several connections may claim
 *   the same routing, as long as they agree about where the
 *   packets are to be sent.
 * - With the current KLIPS, only one outbound IPsec SA bundle can be
 *   used for a particular client.  This is due to a limitation
 *   of using only routing for selection.  So only one IPsec state (SA)
 *   may "own" the eroute.  "eroute_owner" is the serial number of
 *   this state, SOS_NOBODY if there is none.  "routing" indicates
 *   what kind of erouting has been done for this connection, if any.
 *
 * Details on routing is in constants.h
 *
 * Operations on Connections:
 *
 * - add a new connection (with all details) [whack command]
 * - delete a connection (by name) [whack command]
 * - initiate a connection (by name) [whack command]
 * - find a connection (by IP addresses of hosts)
 *   [response to peer request; finding ISAKMP connection for IPsec connection]
 *
 * Some connections are templates, missing the address of the peer
 * (represented by INADDR_ANY).  These are always arranged so that the
 * missing end is "that" (there can only be one missing end).  These can
 * be instantiated (turned into real connections) by Pluto in one of two
 * different ways: Road Warrior Instantiation or Opportunistic
 * Instantiation.  A template connection is marked for Opportunistic
 * Instantiation by specifying the peer client as 0.0.0.0/32 (or the IPV6
 * equivalent).  Otherwise, it is suitable for Road Warrior Instantiation.
 *
 * Instantiation creates a new temporary connection, with the missing
 * details filled in.  The resulting template lasts only as long as there
 * is a state that uses it.
 */

/* connection policy priority: how important this policy is
 * - used to implement eroute-like precedence (augmented by a small
 *   bonus for a routed connection).
 * - a whole number
 * - larger is more important
 * - three subcomponents.  In order of decreasing significance:
 *   + length of source subnet mask (8 bits)
 *   + length of destination subnet mask (8 bits)
 *   + bias (8 bit)
 * - a bias of 1 is added to allow prio BOTTOM_PRIO to be less than all
 *   normal priorities
 * - other bias values are created on the fly to give mild preference
 *   to certaion conditions (eg. routedness)
 * - priority is inherited -- an instance of a policy has the same priority
 *   as the original policy, even though its subnets might be smaller.
 * - display format: n,m
 */
typedef unsigned long policy_prio_t;
#define BOTTOM_PRIO   ((policy_prio_t)0)        /* smaller than any real prio */
#define set_policy_prio(c) { (c)->prio = \
		((policy_prio_t)(c)->spd.this.client.maskbits << 16) \
		| ((policy_prio_t)(c)->spd.that.client.maskbits << 8) \
		| (policy_prio_t)1; }
#define POLICY_PRIO_BUF (3+1+3+1)
extern void fmt_policy_prio(policy_prio_t pp, char buf[POLICY_PRIO_BUF]);

struct virtual_t;

struct end {
	struct id id;
	ip_address
		host_addr,
		host_nexthop,
		host_srcip;
	ip_subnet client;

	bool key_from_DNS_on_demand;
	bool has_client;
	bool has_client_wildcard;
	bool has_port_wildcard;
	bool has_id_wildcards;
	bool has_natip;
	char *updown;
	u_int16_t host_port;        /* host order */
	u_int16_t port;             /* host order */
	u_int8_t protocol;
	cert_t cert;                /* end certificate */
	chunk_t ca;                 /* CA distinguished name */
	struct ietfAttrList *groups;/* access control groups */
	smartcard_t *sc;            /* smartcard reader and key info */
	struct virtual_t *virt;
	bool modecfg;               /* this end: request local address from server */
								/* that end: give local addresses to clients */
	bool hostaccess;            /* allow access to host via iptables INPUT/OUTPUT */
								/* rules if client behind host is a subnet */
	bool allow_any;             /* IP address is subject to change */
	certpolicy_t sendcert;      /* whether or not to send the certificate */
};

struct spd_route {
	struct spd_route *next;
	struct end this;
	struct end that;
	so_serial_t eroute_owner;
	enum routing_t routing;     /* level of routing in place */
	uint32_t reqid;
};

typedef struct connection connection_t;

struct connection {
	char *name;
	bool ikev1;

	lset_t policy;
	time_t sa_ike_life_seconds;
	time_t sa_ipsec_life_seconds;
	time_t sa_rekey_margin;
	unsigned long sa_rekey_fuzz;
	unsigned long sa_keying_tries;

	/* RFC 3706 DPD */
	time_t dpd_delay;
	time_t dpd_timeout;
	dpd_action_t dpd_action;

	char              *log_file_name;       /* name of log file */
	FILE              *log_file;            /* possibly open FILE */
	TAILQ_ENTRY(connection) log_link;     /* linked list of open conns */
	bool               log_file_err;        /* only bitch once */

	struct spd_route spd;

	/* internal fields: */

	unsigned long instance_serial;
	policy_prio_t prio;
	bool instance_initiation_ok;        /* this is an instance of a policy that mandates initiate */
	enum connection_kind kind;
	const struct iface *interface;      /* filled in iff oriented */

	so_serial_t /* state object serial number */
		newest_isakmp_sa,
		newest_ipsec_sa;


#ifdef DEBUG
	lset_t extra_debugging;
#endif

	/* note: if the client is the gateway, the following must be equal */
	sa_family_t addr_family;            /* between gateways */
	sa_family_t tunnel_addr_family;     /* between clients */

	connection_t *policy_next;          /* if multiple policies,
										   next one to apply */

	struct gw_info *gw_info;
	struct alg_info_esp *alg_info_esp;
	struct alg_info_ike *alg_info_ike;

	struct host_pair *host_pair;
	connection_t *hp_next;              /* host pair list link */
	connection_t *ac_next;              /* all connections list link */

	generalName_t *requested_ca;        /* collected certificate requests */
	bool got_certrequest;
};

#define oriented(c) ((c).interface != NULL)
extern bool orient(connection_t *c);

extern bool same_peer_ids(const connection_t *c, const connection_t *d,
						  const struct id *his_id);

/* Format the topology of a connection end, leaving out defaults.
 * Largest left end looks like: client === host : port [ host_id ] --- hop
 * Note: if that==NULL, skip nexthop
 */
#define END_BUF (SUBNETTOT_BUF + ADDRTOT_BUF + IDTOA_BUF + ADDRTOT_BUF + 10)
extern size_t format_end(char *buf, size_t buf_len, const struct end *this,
						 const struct end *that, bool is_left, lset_t policy);

extern void add_connection(const whack_message_t *wm);
extern void initiate_connection(const char *name, int whackfd);
extern void initiate_opportunistic(const ip_address *our_client,
								   const ip_address *peer_client,
								   int transport_proto, bool held, int whackfd);
extern void terminate_connection(const char *nm);
extern void release_connection(connection_t *c, bool relations);
extern void delete_connection(connection_t *c, bool relations);
extern void delete_connections_by_name(const char *name, bool strict);
extern void delete_every_connection(void);
extern char *add_group_instance(connection_t *group, const ip_subnet *target);
extern void remove_group_instance(const connection_t *group, const char *name);
extern void release_dead_interfaces(void);
extern void check_orientations(void);
extern connection_t *route_owner(connection_t *c, struct spd_route **srp,
								 connection_t **erop, struct spd_route **esrp);
extern connection_t *shunt_owner(const ip_subnet *ours, const ip_subnet *his);

extern bool uniqueIDs;  /* --uniqueids? */
extern void ISAKMP_SA_established(connection_t *c, so_serial_t serial);

#define his_id_was_instantiated(c) ((c)->kind == CK_INSTANCE \
	&& (id_is_ipaddr(&(c)->spd.that.id)? \
	sameaddr(&(c)->spd.that.id.ip_addr, &(c)->spd.that.host_addr) : TRUE))

struct state;   /* forward declaration of tag (defined in state.h) */
extern connection_t
	*con_by_name(const char *nm, bool strict),
	*find_host_connection(const ip_address *me, u_int16_t my_port
		, const ip_address *him, u_int16_t his_port, lset_t policy),
	*refine_host_connection(const struct state *st, const struct id *id
		, chunk_t peer_ca),
	*find_client_connection(connection_t *c
		, const ip_subnet *our_net
		, const ip_subnet *peer_net
		, const u_int8_t our_protocol
		, const u_int16_t out_port
		, const u_int8_t peer_protocol
		, const u_int16_t peer_port),
	*find_connection_by_reqid(uint32_t reqid);

extern connection_t *
find_connection_for_clients(struct spd_route **srp
							, const ip_address *our_client
							, const ip_address *peer_client
							, int transport_proto);

extern chunk_t get_peer_ca_and_groups(connection_t *c
	, const ietfAttrList_t **peer_list);

/* instantiating routines
 * Note: connection_discard() is in state.h because all its work
 * is looking through state objects.
 */
struct gw_info; /* forward declaration of tag (defined in dnskey.h) */
struct alg_info;        /* forward declaration of tag (defined in alg_info.h) */
extern connection_t *rw_instantiate(connection_t *c
										 , const ip_address *him
										 , u_int16_t his_port
										 , const ip_subnet *his_net
										 , const struct id *his_id);

extern connection_t *oppo_instantiate(connection_t *c
										   , const ip_address *him
										   , const struct id *his_id
										   , struct gw_info *gw
										   , const ip_address *our_client
										   , const ip_address *peer_client);

extern connection_t
  *build_outgoing_opportunistic_connection(struct gw_info *gw
										   , const ip_address *our_client
										   , const ip_address *peer_client);

/* worst case: "[" serial "] " myclient "=== ..." peer "===" hisclient '\0' */
#define CONN_INST_BUF \
	(2 + 10 + 1 + SUBNETTOT_BUF + 7 + ADDRTOT_BUF + 3 + SUBNETTOT_BUF + 1)

extern void fmt_conn_instance(const connection_t *c
	, char buf[CONN_INST_BUF]);

/* operations on "pending", the structure representing Quick Mode
 * negotiations delayed until a Keying Channel has been negotiated.
 */

struct pending; /* forward declaration (opaque outside connections.c) */

extern void add_pending(int whack_sock
	, struct state *isakmp_sa
	, connection_t *c
	, lset_t policy
	, unsigned long try
	, so_serial_t replacing);

extern void release_pending_whacks(struct state *st, err_t story);
extern void unpend(struct state *st);
extern void update_pending(struct state *os, struct state *ns);
extern void flush_pending_by_state(struct state *st);
extern void show_pending_phase2(const struct host_pair *hp, const struct state *st);

extern void connection_discard(connection_t *c);

/* A template connection's eroute can be eclipsed by
 * either a %hold or an eroute for an instance iff
 * the template is a /32 -> /32.  This requires some special casing.
 */
#define eclipsable(sr) (subnetishost(&(sr)->this.client) && subnetishost(&(sr)->that.client))
extern long eclipse_count;
extern connection_t *eclipsed(connection_t *c, struct spd_route **);


/* print connection status */

extern void show_connections_status(bool all, const char *name);
extern int  connection_compare(const connection_t *ca
	, const connection_t *cb);
extern void update_host_pair(const char *why, connection_t *c
	, const ip_address *myaddr, u_int16_t myport
	, const ip_address *hisaddr, u_int16_t hisport);

#endif /* _CONNECTIONS_H */
