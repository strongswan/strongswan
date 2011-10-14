/* information about connections between hosts and clients
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <arpa/nameser.h>       /* missing from <resolv.h> on old systems */
#include <sys/queue.h>

#include <freeswan.h>
#include "kameipsec.h"

#include <hydra.h>
#include <credentials/certificates/ac.h>
#include <credentials/keys/private_key.h>

#include "constants.h"
#include "defs.h"
#include "myid.h"
#include "x509.h"
#include "ca.h"
#include "crl.h"
#include "certs.h"
#include "ac.h"
#include "smartcard.h"
#include "fetch.h"
#include "connections.h"
#include "foodgroups.h"
#include "demux.h"
#include "state.h"
#include "timer.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "server.h"
#include "kernel.h"
#include "log.h"
#include "keys.h"
#include "adns.h"       /* needs <resolv.h> */
#include "dnskey.h"     /* needs keys.h and adns.h */
#include "whack.h"
#include "alg_info.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "nat_traversal.h"
#include "virtual.h"
#include "whack_attribute.h"
#include "modecfg.h"

static void flush_pending_by_connection(connection_t *c);  /* forward */

static connection_t *connections = NULL;

/* struct host_pair: a nexus of information about a pair of hosts.
 * A host is an IP address, UDP port pair.  This is a debatable choice:
 * - should port be considered (no choice of port in standard)?
 * - should ID be considered (hard because not always known)?
 * - should IP address matter on our end (we don't know our end)?
 * Only oriented connections are registered.
 * Unoriented connections are kept on the unoriented_connections
 * linked list (using hp_next).  For them, host_pair is NULL.
 */

struct host_pair {
	struct {
		ip_address addr;
		u_int16_t port; /* host order */
	} me, him;
	bool initial_connection_sent;
	connection_t *connections;     /* connections with this pair */
	struct pending *pending;    /* awaiting Keying Channel */
	struct host_pair *next;
};

static struct host_pair *host_pairs = NULL;

static connection_t *unoriented_connections = NULL;

/**
 * Check if an id was instantiated by assigning to it the current IP address
 */
bool his_id_was_instantiated(const connection_t *c)
{
	if (c->kind != CK_INSTANCE)
	{
		return FALSE;
	}
	if (id_is_ipaddr(c->spd.that.id))
	{
		identification_t *host;
		bool equal;

		host = identification_create_from_sockaddr((sockaddr_t*)&c->spd.that.host_addr);
		equal = host->equals(host, c->spd.that.id);
		host->destroy(host);
		return equal;
	}
	else
	{
		return TRUE;
	}
}

/**
 * Check to see that IDs of peers match
 */
bool same_peer_ids(const connection_t *c, const connection_t *d,
				   identification_t *his_id)
{
	return d->spd.this.id->equals(d->spd.this.id, c->spd.this.id) &&
		   d->spd.that.id->equals(d->spd.that.id,
								  his_id ? his_id : c->spd.that.id);
}

static struct host_pair *find_host_pair(const ip_address *myaddr,
										u_int16_t myport,
										const ip_address *hisaddr,
										u_int16_t hisport)
{
	struct host_pair *p, *prev;

	/* default hisaddr to an appropriate any */
	if (hisaddr == NULL)
		hisaddr = aftoinfo(addrtypeof(myaddr))->any;

	if (nat_traversal_enabled)
	{
		/**
		 * port is not relevant in host_pair. with nat_traversal we
		 * always use pluto_port (500)
		 */
		myport = pluto_port;
		hisport = pluto_port;
	}

	for (prev = NULL, p = host_pairs; p != NULL; prev = p, p = p->next)
	{
		if (sameaddr(&p->me.addr, myaddr) && p->me.port == myport
		&&  sameaddr(&p->him.addr, hisaddr) && p->him.port == hisport)
		{
			if (prev)
			{
				prev->next = p->next;   /* remove p from list */
				p->next = host_pairs;   /* and stick it on front */
				host_pairs = p;
			}
			break;
		}
	}
	return p;
}

/* find head of list of connections with this pair of hosts */
static connection_t *find_host_pair_connections(const ip_address *myaddr,
													 u_int16_t myport,
													 const ip_address *hisaddr,
														u_int16_t hisport)
{
	struct host_pair *hp = find_host_pair(myaddr, myport, hisaddr, hisport);

	if (nat_traversal_enabled && hp && hisaddr)
	{
		connection_t *c;

		for (c = hp->connections; c != NULL; c = c->hp_next)
		{
			if (c->spd.this.host_port == myport && c->spd.that.host_port == hisport)
				return c;
		}
		return NULL;
	}
	return hp == NULL? NULL : hp->connections;
}

static void connect_to_host_pair(connection_t *c)
{
	if (oriented(*c))
	{
		struct host_pair *hp;

		ip_address his_addr = (c->spd.that.allow_any)
							  ? *aftoinfo(addrtypeof(&c->spd.that.host_addr))->any
							  : c->spd.that.host_addr;

		hp = find_host_pair(&c->spd.this.host_addr, c->spd.this.host_port
			, &his_addr, c->spd.that.host_port);

		if (hp == NULL)
		{
			/* no suitable host_pair -- build one */
			hp = malloc_thing(struct host_pair);
			hp->me.addr = c->spd.this.host_addr;
			hp->him.addr = his_addr;
			hp->me.port = nat_traversal_enabled ? pluto_port : c->spd.this.host_port;
			hp->him.port = nat_traversal_enabled ? pluto_port : c->spd.that.host_port;
			hp->initial_connection_sent = FALSE;
			hp->connections = NULL;
			hp->pending = NULL;
			hp->next = host_pairs;
			host_pairs = hp;
		}
		c->host_pair = hp;
		c->hp_next = hp->connections;
		hp->connections = c;
	}
	else
	{
		/* since this connection isn't oriented, we place it
		 * in the unoriented_connections list instead.
		 */
		c->host_pair = NULL;
		c->hp_next = unoriented_connections;
		unoriented_connections = c;
	}
}

/* find a connection by name.
 * If strict, don't accept a CK_INSTANCE.
 * Move the winner (if any) to the front.
 * If none is found, and strict, a diagnostic is logged to whack.
 */
connection_t *con_by_name(const char *nm, bool strict)
{
	connection_t *p, *prev;

	for (prev = NULL, p = connections; ; prev = p, p = p->ac_next)
	{
		if (p == NULL)
		{
			if (strict)
				whack_log(RC_UNKNOWN_NAME
					, "no connection named \"%s\"", nm);
			break;
		}
		if (streq(p->name, nm)
		&& (!strict || p->kind != CK_INSTANCE))
		{
			if (prev)
			{
				prev->ac_next = p->ac_next;     /* remove p from list */
				p->ac_next = connections;       /* and stick it on front */
				connections = p;
			}
			break;
		}
	}
	return p;
}

void release_connection(connection_t *c, bool relations)
{
	if (c->kind == CK_INSTANCE)
	{
		/* This does everything we need.
		 * Note that we will be called recursively by delete_connection,
		 * but kind will be CK_GOING_AWAY.
		 */
		delete_connection(c, relations);
	}
	else
	{
		flush_pending_by_connection(c);
		delete_states_by_connection(c, relations);
		unroute_connection(c);
	}
}

/* Delete a connection */

#define list_rm(etype, enext, e, ehead) { \
		etype **ep; \
		for (ep = &(ehead); *ep != (e); ep = &(*ep)->enext) \
			passert(*ep != NULL);    /* we must not come up empty-handed */ \
		*ep = (e)->enext; \
	}


void delete_connection(connection_t *c, bool relations)
{
	modecfg_attribute_t *ca;
	connection_t *old_cur_connection;
	identification_t *client_id;

	old_cur_connection = cur_connection == c? NULL : cur_connection;
#ifdef DEBUG
	lset_t old_cur_debugging = cur_debugging;
#endif

	set_cur_connection(c);

	/* Must be careful to avoid circularity:
	 * we mark c as going away so it won't get deleted recursively.
	 */
	passert(c->kind != CK_GOING_AWAY);
	if (c->kind == CK_INSTANCE)
	{
		plog("deleting connection \"%s\" instance with peer %s {isakmp=#%lu/ipsec=#%lu}"
			 , c->name
			 , ip_str(&c->spd.that.host_addr)
			 , c->newest_isakmp_sa, c->newest_ipsec_sa);
		c->kind = CK_GOING_AWAY;
	}
	else
	{
		plog("deleting connection");
	}
	release_connection(c, relations);   /* won't delete c */

	if (c->kind == CK_GROUP)
	{
		delete_group(c);
	}

	/* free up any logging resources */
	perpeer_logfree(c);

	/* find and delete c from connections list */
	list_rm(connection_t, ac_next, c, connections);
	cur_connection = old_cur_connection;

	/* find and delete c from the host pair list */
	if (c->host_pair == NULL)
	{
		if (c->ikev1)
		{
			list_rm(connection_t, hp_next, c, unoriented_connections);
		}
	}
	else
	{
		struct host_pair *hp = c->host_pair;

		list_rm(connection_t, hp_next, c, hp->connections);
		c->host_pair = NULL;    /* redundant, but safe */

		/* if there are no more connections with this host_pair
		 * and we haven't even made an initial contact, let's delete
		 * this guy in case we were created by an attempted DOS attack.
		 */
		if (hp->connections == NULL
		&& !hp->initial_connection_sent)
		{
			passert(hp->pending == NULL);       /* ??? must deal with this! */
			list_rm(struct host_pair, next, hp, host_pairs);
			free(hp);
		}
	}
	if (c->kind != CK_GOING_AWAY)
	{
		free(c->spd.that.virt);
	}

	client_id = (c->xauth_identity) ? c->xauth_identity : c->spd.that.id;

	/* release virtual IP address lease if any */
	if (c->spd.that.modecfg && c->spd.that.pool &&
		!c->spd.that.host_srcip->is_anyaddr(c->spd.that.host_srcip))
	{
		hydra->attributes->release_address(hydra->attributes, c->spd.that.pool,
										   c->spd.that.host_srcip, client_id);
	}

	/* release requested attributes if any */
	if (c->requested)
	{
		c->requested->destroy_function(c->requested,
									  (void*)modecfg_attribute_destroy);
	}

	/* release other attributes if any */
	if (c->attributes)
	{
		while (c->attributes->remove_last(c->attributes, (void **)&ca) == SUCCESS)
		{
			hydra->attributes->release(hydra->attributes, ca->handler,
									   client_id, ca->type, ca->value);
			modecfg_attribute_destroy(ca);
		}
		c->attributes->destroy(c->attributes);
	}

	if (c->kind != CK_GOING_AWAY)
	{
		whack_attr->del_pool(whack_attr, c->name);
	}

	/* free internal data */
#ifdef DEBUG
	cur_debugging = old_cur_debugging;
#endif
	free(c->name);
	DESTROY_IF(c->xauth_identity);
	DESTROY_IF(c->spd.this.id);
	DESTROY_IF(c->spd.this.ca);
	DESTROY_IF(c->spd.this.groups);
	DESTROY_IF(c->spd.this.host_srcip);
	free(c->spd.this.updown);
	free(c->spd.this.pool);
	DESTROY_IF(c->spd.that.id);
	DESTROY_IF(c->spd.that.ca);
	DESTROY_IF(c->spd.that.groups);
	DESTROY_IF(c->spd.that.host_srcip);
	free(c->spd.that.updown);
	free(c->spd.that.pool);
	if (c->requested_ca)
	{
		c->requested_ca->destroy_offset(c->requested_ca,
										offsetof(identification_t, destroy));
	}
#ifdef ADNS
	gw_delref(&c->gw_info);
#endif
	lock_certs_and_keys("delete_connection");
	cert_release(c->spd.this.cert);
	scx_release(c->spd.this.sc);
	cert_release(c->spd.that.cert);
	scx_release(c->spd.that.sc);
	unlock_certs_and_keys("delete_connection");

	alg_info_delref((struct alg_info **)&c->alg_info_esp);
	alg_info_delref((struct alg_info **)&c->alg_info_ike);

	free(c);
}

/* Delete connections with the specified name */
void delete_connections_by_name(const char *name, bool strict)
{
	connection_t *c = con_by_name(name, strict);

	for (; c != NULL; c = con_by_name(name, FALSE))
		delete_connection(c, FALSE);
}

void delete_every_connection(void)
{
	while (connections)
	{
		delete_connection(connections, TRUE);
	}
}

void release_dead_interfaces(void)
{
	struct host_pair *hp;

	for (hp = host_pairs; hp != NULL; hp = hp->next)
	{
		connection_t **pp
			, *p;

		for (pp = &hp->connections; (p = *pp) != NULL; )
		{
			if (p->interface->change == IFN_DELETE)
			{
				/* this connection's interface is going away */
				enum connection_kind k = p->kind;

				release_connection(p, TRUE);

				if (k <= CK_PERMANENT)
				{
					/* The connection should have survived release:
					 * move it to the unoriented_connections list.
					 */
					passert(p == *pp);

					p->interface = NULL;

					*pp = p->hp_next;   /* advance *pp */
					p->host_pair = NULL;
					p->hp_next = unoriented_connections;
					unoriented_connections = p;
				}
				else
				{
					/* The connection should have vanished,
					 * but the previous connection remains.
					 */
					passert(p != *pp);
				}
			}
			else
			{
				pp = &p->hp_next;       /* advance pp */
			}
		}
	}
}

/* adjust orientations of connections to reflect newly added interfaces */
void check_orientations(void)
{
	/* try to orient all the unoriented connections */
	{
		connection_t *c = unoriented_connections;

		unoriented_connections = NULL;

		while (c)
		{
			connection_t *nxt = c->hp_next;

			(void)orient(c);
			connect_to_host_pair(c);
			c = nxt;
		}
	}

	/* Check that no oriented connection has become double-oriented.
	 * In other words, the far side must not match one of our new interfaces.
	 */
	{
		struct iface *i;

		for (i = interfaces; i != NULL; i = i->next)
		{
			if (i->change == IFN_ADD)
			{
				struct host_pair *hp;

				for (hp = host_pairs; hp != NULL; hp = hp->next)
				{
					if (sameaddr(&hp->him.addr, &i->addr)
						&& hp->him.port == pluto_port)
					{
						/* bad news: the whole chain of connections
						 * hanging off this host pair has both sides
						 * matching an interface.
						 * We'll get rid of them, using orient and
						 * connect_to_host_pair.  But we'll be lazy
						 * and not ditch the host_pair itself (the
						 * cost of leaving it is slight and cannot
						 * be induced by a foe).
						 */
						connection_t *c = hp->connections;

						hp->connections = NULL;
						while (c)
						{
							connection_t *nxt = c->hp_next;

							c->interface = NULL;
							(void)orient(c);
							connect_to_host_pair(c);
							c = nxt;
						}
					}
				}
			}
		}
	}
}

static err_t default_end(struct end *e, ip_address *dflt_nexthop)
{
	err_t ugh = NULL;
	int af = addrtypeof(&e->host_addr);

	if (af != AF_INET && af != AF_INET6)
	{
		return "unknown address family in default_end";
	}

	/* default ID to IP (but only if not NO_IP -- WildCard) */
	if (e->id->get_type(e->id) == ID_ANY && !isanyaddr(&e->host_addr))
	{
		e->id->destroy(e->id);
		e->id = identification_create_from_sockaddr((sockaddr_t*)&e->host_addr);
		e->has_id_wildcards = FALSE;
	}

	/* default nexthop to other side */
	if (isanyaddr(&e->host_nexthop))
	{
		e->host_nexthop = *dflt_nexthop;
	}

	/* default client to subnet containing only self
	 * XXX This may mean that the client's address family doesn't match
	 * tunnel_addr_family.
	 */
	if (!e->has_client)
	{
		ugh = addrtosubnet(&e->host_addr, &e->client);
	}
	return ugh;
}

/* Format the topology of a connection end, leaving out defaults.
 * Largest left end looks like: client === host : port [ host_id ] --- hop
 * Note: if that==NULL, skip nexthop
 * Returns strlen of formated result (length excludes NUL at end).
 */
size_t format_end(char *buf, size_t buf_len, const struct end *this,
				 const struct end *that, bool is_left, lset_t policy)
{
	char client[BUF_LEN];
	const char *client_sep = "";
	char protoport[sizeof(":255/65535")];
	const char *host = NULL;
	char host_space[ADDRTOT_BUF];
	char host_port[sizeof(":65535")];
	char host_id[BUF_LEN + 2];
	char hop[ADDRTOT_BUF];
	const char *hop_sep = "";
	const char *open_brackets  = "";
	const char *close_brackets = "";

	if (isanyaddr(&this->host_addr))
	{
		switch (policy & (POLICY_GROUP | POLICY_OPPO))
		{
		case POLICY_GROUP:
			host = "%group";
			break;
		case POLICY_OPPO:
			host = "%opportunistic";
			break;
		case POLICY_GROUP | POLICY_OPPO:
			host = "%opportunisticgroup";
			break;
		default:
			host = "%any";
			break;
		}
	}

	client[0] = '\0';

	if (is_virtual_end(this) && isanyaddr(&this->host_addr))
	{
		host = "%virtual";
	}

	/* [client===] */
	if (this->has_client)
	{
		ip_address client_net, client_mask;

		networkof(&this->client, &client_net);
		maskof(&this->client, &client_mask);
		client_sep = "===";

		/* {client_subnet_wildcard} */
		if (this->has_client_wildcard)
		{
			open_brackets  = "{";
			close_brackets = "}";
		}

		if (isanyaddr(&client_net) && isanyaddr(&client_mask)
		&& (policy & (POLICY_GROUP | POLICY_OPPO)))
		{
			client_sep = "";    /* boring case */
		}
		else if (subnetisnone(&this->client))
		{
			strncpy(client, "?", sizeof(client));
		}
		else
		{
			subnettot(&this->client, 0, client, sizeof(client));
		}
	}
	else if (this->modecfg && this->host_srcip->is_anyaddr(this->host_srcip))
	{
		/* we are mode config client, or a server with a pool */
		client_sep = "===";
		client[0] = '%';
		strncpy(client+1, this->pool ?: "modecfg", sizeof(client)-1);
	}

	/* host */
	if (host == NULL)
	{
		addrtot(&this->host_addr, 0, host_space, sizeof(host_space));
		host = host_space;
	}

	host_port[0] = '\0';
	if (this->host_port != IKE_UDP_PORT)
	{
		snprintf(host_port, sizeof(host_port), ":%u", this->host_port);
	}

	/* payload portocol and port */
	protoport[0] = '\0';
	if (this->has_port_wildcard)
	{
		snprintf(protoport, sizeof(protoport), ":%u/%%any", this->protocol);
	}
	else if (this->port || this->protocol)
	{
		snprintf(protoport, sizeof(protoport), ":%u/%u", this->protocol
			, this->port);
	}

	/* id */
	snprintf(host_id, sizeof(host_id), "[%Y]", this->id);

	/* [---hop] */
	hop[0] = '\0';
	hop_sep = "";
	if (that && !sameaddr(&this->host_nexthop, &that->host_addr))
	{
		addrtot(&this->host_nexthop, 0, hop, sizeof(hop));
		hop_sep = "---";
	}

	if (is_left)
	{
		snprintf(buf, buf_len, "%s%s%s%s%s%s%s%s%s%s%s"
			, open_brackets, client, close_brackets, client_sep
			, this->allow_any? "%":""
			, host, host_port, host_id, protoport
			, hop_sep, hop);
	}
	else
	{
		snprintf(buf, buf_len, "%s%s%s%s%s%s%s%s%s%s%s"
			, hop, hop_sep
			, this->allow_any? "%":""
			, host, host_port, host_id, protoport, client_sep
			, open_brackets, client, close_brackets);
	}
	return strlen(buf);
}

/* format topology of a connection.
 * Two symmetric ends separated by ...
 */
#define CONNECTION_BUF  (2 * (END_BUF - 1) + 4)

static size_t format_connection(char *buf, size_t buf_len,
								const connection_t *c,
								struct spd_route *sr)
{
	size_t w = format_end(buf, buf_len, &sr->this, &sr->that, TRUE, LEMPTY);

	w += snprintf(buf + w, buf_len - w, "...");
	return w + format_end(buf + w, buf_len - w, &sr->that, &sr->this, FALSE, c->policy);
}

static void unshare_connection_strings(connection_t *c)
{
	c->name = clone_str(c->name);
	if (c->xauth_identity)
	{
		c->xauth_identity = c->xauth_identity->clone(c->xauth_identity);
	}
	c->spd.this.id = c->spd.this.id->clone(c->spd.this.id);
	c->spd.this.pool = clone_str(c->spd.this.pool);
	c->spd.this.updown = clone_str(c->spd.this.updown);
	c->spd.this.host_srcip = c->spd.this.host_srcip->clone(c->spd.this.host_srcip);
	scx_share(c->spd.this.sc);
	cert_share(c->spd.this.cert);
	if (c->spd.this.ca)
	{
		c->spd.this.ca = c->spd.this.ca->clone(c->spd.this.ca);
	}
	if (c->spd.this.groups)
	{
		c->spd.this.groups = c->spd.this.groups->get_ref(c->spd.this.groups);
	}
	c->spd.that.id = c->spd.that.id->clone(c->spd.that.id);
	c->spd.that.pool = clone_str(c->spd.that.pool);
	c->spd.that.updown = clone_str(c->spd.that.updown);
	c->spd.that.host_srcip = c->spd.that.host_srcip->clone(c->spd.that.host_srcip);
	scx_share(c->spd.that.sc);
	cert_share(c->spd.that.cert);
	if (c->spd.that.ca)
	{
		c->spd.that.ca = c->spd.that.ca->clone(c->spd.that.ca);
	}
	if (c->spd.that.groups)
	{
		c->spd.that.groups = c->spd.that.groups->get_ref(c->spd.that.groups);
	}

	/* increment references to algo's */
	alg_info_addref((struct alg_info *)c->alg_info_esp);
	alg_info_addref((struct alg_info *)c->alg_info_ike);
}

static void load_end_certificate(char *filename, struct end *dst)
{
	time_t notBefore, notAfter;
	cert_t *cert = NULL;
	certificate_t *certificate;
	bool cached_cert = FALSE;

	/* initialize end certificate */
	dst->cert = NULL;

	/* initialize smartcard info record */
	dst->sc = NULL;

	if (filename)
	{
		if (scx_on_smartcard(filename))
		{
			/* load cert from smartcard */
			cert = scx_load_cert(filename, &dst->sc, &cached_cert);
		}
		else
		{
			/* load cert from file */
			cert = load_host_cert(filename);
		}
	}

	if (cert)
	{
		certificate = cert->cert;

		if (dst->id->get_type(dst->id) == ID_ANY ||
			!certificate->has_subject(certificate, dst->id))
		{
			plog( "  id '%Y' not confirmed by certificate, defaulting to '%Y'",
				 dst->id, certificate->get_subject(certificate));
			dst->id->destroy(dst->id);
			dst->id = certificate->get_subject(certificate);
			dst->id = dst->id->clone(dst->id);
		}

		if (cached_cert)
		{
			dst->cert = cert;
		}
		else
		{
			if (!certificate->get_validity(certificate, NULL, &notBefore, &notAfter))
			{
				plog("certificate is invalid (valid from %T to %T)",
					 &notBefore, FALSE, &notAfter, FALSE);
				cert_free(cert);
				return;
			}
			DBG(DBG_CONTROL,
				DBG_log("certificate is valid")
			)
			add_public_key_from_cert(cert, notAfter, DAL_LOCAL);
			dst->cert = cert_add(cert);
		}
		certificate = dst->cert->cert;

		/* if no CA is defined, use issuer as default */
		if (dst->ca == NULL && certificate->get_type(certificate) == CERT_X509)
		{
			identification_t *issuer;

			issuer = certificate->get_issuer(certificate);
			dst->ca = issuer->clone(issuer);
		}

		/* cache the certificate that was last retrieved from the smartcard */
		if (dst->sc)
		{
			if (!dst->sc->last_cert ||
			    !certificate->equals(certificate, dst->sc->last_cert->cert))
			{
				lock_certs_and_keys("load_end_certificates");
				cert_release(dst->sc->last_cert);
				dst->sc->last_cert = dst->cert;
				cert_share(dst->cert);
				unlock_certs_and_keys("load_end_certificates");
			}
			time(&dst->sc->last_load);
		}
	}
	scx_share(dst->sc);
	cert_share(dst->cert);
}

static bool extract_end(struct end *dst, const whack_end_t *src,
						const char *name, bool is_left)
{
	bool same_ca = FALSE;

	dst->is_left = is_left;
	dst->id = identification_create_from_string(src->id);
	dst->ca = NULL;

	/* decode CA distinguished name, if any */
	if (src->ca)
	{
		if streq(src->ca, "%same")
		{
			same_ca = TRUE;
		}
		else if (!streq(src->ca, "%any"))
		{
			dst->ca = identification_create_from_string(src->ca);
			if (dst->ca->get_type(dst->ca) != ID_DER_ASN1_DN)
			{
				plog("bad CA string '%s', ignored", src->ca);
				dst->ca->destroy(dst->ca);
				dst->ca = NULL;
			}
		}
	}

	/* load local end certificate and extract ID, if any */
	load_end_certificate(src->cert, dst);

	/* does id has wildcards? */
	dst->has_id_wildcards = dst->id->contains_wildcards(dst->id);

	/* decode group attributes, if any */
	if (src->groups)
	{
		dst->groups = ietf_attributes_create_from_string(src->groups);
	}

	/* the rest is simple copying of corresponding fields */
	dst->host_addr = src->host_addr;
	dst->host_nexthop = src->host_nexthop;
	dst->host_srcip = host_create_from_sockaddr((sockaddr_t*)&src->host_srcip);
	dst->has_natip = src->has_natip;
	dst->client = src->client;
	dst->protocol = src->protocol;
	dst->port = src->port;
	dst->has_port_wildcard = src->has_port_wildcard;
	dst->key_from_DNS_on_demand = src->key_from_DNS_on_demand;
	dst->has_client = src->has_client;
	dst->has_client_wildcard = src->has_client_wildcard;
	dst->modecfg = src->modecfg;
	dst->hostaccess = src->hostaccess;
	dst->allow_any = src->allow_any;
	dst->sendcert = src->sendcert;
	dst->updown = clone_str(src->updown);
	dst->host_port = src->host_port;

	/* if the sourceip netmask is zero a named pool exists */
	if (src->sourceip_mask == 0)
	{
		dst->pool = clone_str(src->sourceip);
	}

	/* if host sourceip is defined but no client is present
	 * behind the host then set client to sourceip/32
	 */
	if (!dst->host_srcip->is_anyaddr(dst->host_srcip) &&
		!dst->has_natip && !dst->has_client)
	{
		ip_address addr;
		err_t ugh;

		addr = *(ip_address*)dst->host_srcip->get_sockaddr(dst->host_srcip);
		ugh = addrtosubnet(&addr, &dst->client);

		if (ugh)
		{
			plog("could not assign host sourceip to client subnet");
		}
		else
		{
			dst->has_client = TRUE;
		}
	}
	return same_ca;
}

static bool check_connection_end(const whack_end_t *this,
								 const whack_end_t *that,
								 const whack_message_t *wm)
{
	if (wm->addr_family != addrtypeof(&this->host_addr)
	|| wm->addr_family != addrtypeof(&this->host_nexthop)
	|| (this->has_client? wm->tunnel_addr_family : wm->addr_family)
	  != subnettypeof(&this->client)
	|| subnettypeof(&this->client) != subnettypeof(&that->client))
	{
		/* this should have been diagnosed by whack, so we need not be clear
		 * !!! overloaded use of RC_CLASH
		 */
		loglog(RC_CLASH, "address family inconsistency in connection");
		return FALSE;
	}

	if (isanyaddr(&that->host_addr))
	{
		/* other side is wildcard: we must check if other conditions met */
		if (isanyaddr(&this->host_addr))
		{
			loglog(RC_ORIENT, "connection must specify host IP address for our side");
			return FALSE;
		}
	}

	if (this->virt && (!isanyaddr(&this->host_addr) || this->has_client))
	{
		loglog(RC_CLASH,
			"virtual IP must only be used with %%any and without client");
		return FALSE;
	}

	return TRUE;        /* happy */
}

connection_t *find_connection_by_reqid(uint32_t reqid)
{
	connection_t *c;

	reqid &= ~3;
	for (c = connections; c != NULL; c = c->ac_next)
	{
		if (c->spd.reqid == reqid)
		{
			return c;
		}
	}

	return NULL;
}

static uint32_t gen_reqid(void)
{
	uint32_t start;
	static uint32_t reqid = IPSEC_MANUAL_REQID_MAX & ~3;

	start = reqid;
	do {
		reqid += 4;
		if (reqid == 0)
		{
			reqid = (IPSEC_MANUAL_REQID_MAX & ~3) + 4;
		}
		if (!find_connection_by_reqid(reqid))
		{
			return reqid;
		}
	} while (reqid != start);

	exit_log("unable to allocate reqid");
	return 0; /* never reached ... */
}

void add_connection(const whack_message_t *wm)
{
	if (con_by_name(wm->name, FALSE) != NULL)
	{
		loglog(RC_DUPNAME, "attempt to redefine connection \"%s\"", wm->name);
	}
	else if (wm->right.protocol != wm->left.protocol)
	{
		/* this should haven been diagnosed by whack
		 * !!! overloaded use of RC_CLASH
		 */
		loglog(RC_CLASH, "the protocol must be the same for leftport and rightport");
	}
	else if (check_connection_end(&wm->right, &wm->left, wm)
	&& check_connection_end(&wm->left, &wm->right, wm))
	{
		bool same_rightca, same_leftca;
		connection_t *c = malloc_thing(connection_t);

		zero(c);
		c->name   = clone_str(wm->name);
		c->ikev1  = wm->ikev1;
		c->policy = wm->policy;

		if ((c->policy & POLICY_COMPRESS) && !can_do_IPcomp)
		{
			loglog(RC_COMMENT
				, "ignoring --compress in \"%s\" because kernel does not support IPCOMP"
				, c->name);
		}

		if (wm->esp)
		{
			 DBG(DBG_CONTROL,
				DBG_log("from whack: got --esp=%s", wm->esp ? wm->esp: "NULL")
			)
			c->alg_info_esp = alg_info_esp_create_from_str(wm->esp? wm->esp : "");

			DBG(DBG_CRYPT|DBG_CONTROL,
				static char buf[BUF_LEN]="<NULL>";

				if (c->alg_info_esp)
				{
					alg_info_snprint(buf, sizeof(buf)
							,(struct alg_info *)c->alg_info_esp);
				}
				DBG_log("esp proposal: %s", buf);
			)
			if (c->alg_info_esp)
			{
				if (c->alg_info_esp->alg_info_cnt == 0)
				{
					 loglog(RC_LOG_SERIOUS, "got 0 esp transforms");
				}
			}
			else
			{
				loglog(RC_LOG_SERIOUS, "syntax error in esp string");
			}
		}

		if (wm->ike)
		{
			DBG(DBG_CONTROL,
				DBG_log("from whack: got --ike=%s", wm->ike ? wm->ike: "NULL")
			)
			c->alg_info_ike= alg_info_ike_create_from_str(wm->ike? wm->ike : "");

			DBG(DBG_CRYPT|DBG_CONTROL,
				static char buf[BUF_LEN]="<NULL>";

				if (c->alg_info_ike)
				{
					alg_info_snprint(buf, sizeof(buf)
							, (struct alg_info *)c->alg_info_ike);
				}
				DBG_log("ike proposal: %s", buf);
			)
			if (c->alg_info_ike)
			{
				if (c->alg_info_ike->alg_info_cnt == 0)
				{
					loglog(RC_LOG_SERIOUS, "got 0 ike transforms");
				}
			}
			else
			{
				loglog(RC_LOG_SERIOUS, "syntax error in ike string");
			}
		}

		if (wm->xauth_identity)
		{
			c->xauth_identity
					= identification_create_from_string(wm->xauth_identity);
		}

		c->sa_ike_life_seconds = wm->sa_ike_life_seconds;
		c->sa_ipsec_life_seconds = wm->sa_ipsec_life_seconds;
		c->sa_rekey_margin = wm->sa_rekey_margin;
		c->sa_rekey_fuzz = wm->sa_rekey_fuzz;
		c->sa_keying_tries = wm->sa_keying_tries;

		/* RFC 3706 DPD */
		c->dpd_delay = wm->dpd_delay;
		c->dpd_timeout = wm->dpd_timeout;
		c->dpd_action = wm->dpd_action;

		c->addr_family = wm->addr_family;
		c->tunnel_addr_family = wm->tunnel_addr_family;

		c->requested_ca = NULL;
		same_leftca  = extract_end(&c->spd.this, &wm->left, wm->name, TRUE);
		same_rightca = extract_end(&c->spd.that, &wm->right, wm->name, FALSE);

		if (same_rightca && c->spd.this.ca)
		{
			c->spd.that.ca = c->spd.this.ca->clone(c->spd.this.ca);
		}
		else if (same_leftca && c->spd.that.ca)
		{
			c->spd.this.ca = c->spd.that.ca->clone(c->spd.that.ca);
		}

		default_end(&c->spd.this, &c->spd.that.host_addr);
		default_end(&c->spd.that, &c->spd.this.host_addr);

		/* force any wildcard host IP address, any wildcard subnet
		 * or any wildcard ID to that end
		 */
		if (isanyaddr(&c->spd.this.host_addr) || c->spd.this.has_client_wildcard
		|| c->spd.this.has_port_wildcard || c->spd.this.has_id_wildcards
		|| c->spd.this.allow_any)
		{
			struct end t = c->spd.this;

			c->spd.this = c->spd.that;
			c->spd.that = t;
		}

		c->spd.next = NULL;
		c->spd.reqid = wm->reqid ?: gen_reqid();

		c->spd.mark_in.value = wm->mark_in.value;
		c->spd.mark_in.mask = wm->mark_in.mask;
		c->spd.mark_out.value = wm->mark_out.value;
		c->spd.mark_out.mask = wm->mark_out.mask;

		/* set internal fields */
		c->instance_serial = 0;
		c->ac_next = connections;
		connections = c;
		c->interface = NULL;
		c->spd.routing = RT_UNROUTED;
		c->newest_isakmp_sa = SOS_NOBODY;
		c->newest_ipsec_sa = SOS_NOBODY;
		c->spd.eroute_owner = SOS_NOBODY;

		if (c->policy & POLICY_GROUP)
		{
			c->kind = CK_GROUP;
			add_group(c);
		}
		else if ((isanyaddr(&c->spd.that.host_addr) && !NEVER_NEGOTIATE(c->policy))
		|| c->spd.that.has_client_wildcard || c->spd.that.has_port_wildcard
		|| c->spd.that.has_id_wildcards || c->spd.that.allow_any)
		{
			/* Opportunistic or Road Warrior or wildcard client subnet
			 * or wildcard ID */
			c->kind = CK_TEMPLATE;
		}
		else
		{
			c->kind = CK_PERMANENT;
		}
		set_policy_prio(c);     /* must be after kind is set */

#ifdef DEBUG
		c->extra_debugging = wm->debugging;
#endif

		c->gw_info = NULL;

		passert(!(wm->left.virt && wm->right.virt));
		if (wm->left.virt || wm->right.virt)
		{
			passert(isanyaddr(&c->spd.that.host_addr));
			c->spd.that.virt = create_virtual(c,
				wm->left.virt ? wm->left.virt : wm->right.virt);
			if (c->spd.that.virt)
				c->spd.that.has_client = TRUE;
		}

		(void)orient(c);

		/* if rightsourceip defines a subnet then create an in-memory pool */
		if (whack_attr->add_pool(whack_attr, c->name,
							c->spd.this.is_left ? &wm->right : &wm->left))
		{
			c->spd.that.pool = clone_str(c->name);
			c->spd.that.modecfg = TRUE;
			c->spd.that.has_client = FALSE;
			/* reset the host_srcip so that it gets assigned in modecfg */
			DESTROY_IF(c->spd.that.host_srcip);
			c->spd.that.host_srcip = host_create_any(AF_INET);
		}

		if (c->ikev1)
		{
			connect_to_host_pair(c);
		}

		/* log all about this connection */
		plog("added connection description \"%s\"", c->name);
		DBG(DBG_CONTROL,
			char topo[BUF_LEN];

			(void) format_connection(topo, sizeof(topo), c, &c->spd);

			DBG_log("%s", topo);

			/* Make sure that address families can be correctly inferred
			 * from printed ends.
			 */
			passert(c->addr_family == addrtypeof(&c->spd.this.host_addr)
				&& c->addr_family == addrtypeof(&c->spd.this.host_nexthop)
				&& (c->spd.this.has_client? c->tunnel_addr_family : c->addr_family)
				  == subnettypeof(&c->spd.this.client)

				&& c->addr_family == addrtypeof(&c->spd.that.host_addr)
				&& c->addr_family == addrtypeof(&c->spd.that.host_nexthop)
				&& (c->spd.that.has_client? c->tunnel_addr_family : c->addr_family)
				  == subnettypeof(&c->spd.that.client));

			DBG_log("ike_life: %lus; ipsec_life: %lus; rekey_margin: %lus;"
				" rekey_fuzz: %lu%%; keyingtries: %lu; policy: %s"
				, (unsigned long) c->sa_ike_life_seconds
				, (unsigned long) c->sa_ipsec_life_seconds
				, (unsigned long) c->sa_rekey_margin
				, (unsigned long) c->sa_rekey_fuzz
				, (unsigned long) c->sa_keying_tries
				, prettypolicy(c->policy));
		);
	}
}

/* Derive a template connection from a group connection and target.
 * Similar to instantiate().  Happens at whack --listen.
 * Returns name of new connection.  May be NULL.
 * Caller is responsible for freeing.
 */
char *add_group_instance(connection_t *group, const ip_subnet *target)
{
	char namebuf[100], targetbuf[SUBNETTOT_BUF];
	connection_t *t;
	char *name = NULL;

	passert(group->kind == CK_GROUP);
	passert(oriented(*group));

	/* manufacture a unique name for this template */
	subnettot(target, 0, targetbuf, sizeof(targetbuf));
	snprintf(namebuf, sizeof(namebuf), "%s#%s", group->name, targetbuf);

	if (con_by_name(namebuf, FALSE) != NULL)
	{
		loglog(RC_DUPNAME, "group name + target yields duplicate name \"%s\""
			, namebuf);
	}
	else
	{
		t = clone_thing(*group);
		t->name = namebuf;
		unshare_connection_strings(t);
		name = clone_str(t->name);
		t->spd.that.client = *target;
		t->policy &= ~(POLICY_GROUP | POLICY_GROUTED);
		t->kind = isanyaddr(&t->spd.that.host_addr) && !NEVER_NEGOTIATE(t->policy)
			? CK_TEMPLATE : CK_INSTANCE;

		/* reset log file info */
		t->log_file_name = NULL;
		t->log_file = NULL;
		t->log_file_err = FALSE;

		t->spd.reqid = gen_reqid();

		if (t->spd.that.virt)
		{
			DBG_log("virtual_ip not supported in group instance");
			t->spd.that.virt = NULL;
		}

		/* add to connections list */
		t->ac_next = connections;
		connections = t;

		/* same host_pair as parent: stick after parent on list */
		group->hp_next = t;

		/* route if group is routed */
		if (group->policy & POLICY_GROUTED)
		{
			if (!trap_connection(t))
				whack_log(RC_ROUTE, "could not route");
		}
	}
	return name;
}

/* an old target has disappeared for a group: delete instance */
void remove_group_instance(const connection_t *group USED_BY_DEBUG,
						   const char *name)
{
	passert(group->kind == CK_GROUP);
	passert(oriented(*group));

	delete_connections_by_name(name, FALSE);
}

/* Common part of instantiating a Road Warrior or Opportunistic connection.
 * his_id can be used to carry over an ID discovered in Phase 1.
 * It must not disagree with the one in c, but if that is unspecified,
 * the new connection will use his_id.
 * If his_id is NULL, and c.that.id is uninstantiated (ID_ANY), the
 * new connection will continue to have an uninstantiated that.id.
 * Note: instantiation does not affect port numbers.
 *
 * Note that instantiate can only deal with a single SPD/eroute.
 */
static connection_t *instantiate(connection_t *c, const ip_address *him,
								 u_int16_t his_port, identification_t *his_id)
{
	connection_t *d;

	passert(c->kind == CK_TEMPLATE);
	passert(c->spd.next == NULL);

	c->instance_serial++;
	d = clone_thing(*c);
	d->spd.that.allow_any = FALSE;

	if (his_id)
	{
		d->spd.that.id = his_id;
		d->spd.that.has_id_wildcards = FALSE;
	}
	unshare_connection_strings(d);
	if (d->spd.this.groups)
	{
		d->spd.this.groups = d->spd.this.groups->get_ref(d->spd.this.groups);
	}
	if (d->spd.that.groups)
	{
		d->spd.that.groups = d->spd.that.groups->get_ref(d->spd.that.groups);
	}
	d->kind = CK_INSTANCE;

	passert(oriented(*d));
	d->spd.that.host_addr = *him;
	setportof(htons(c->spd.that.port), &d->spd.that.host_addr);

	if (his_port) d->spd.that.host_port = his_port;

	default_end(&d->spd.that, &d->spd.this.host_addr);

	/* We cannot guess what our next_hop should be, but if it was
	 * explicitly specified as 0.0.0.0, we set it to be him.
	 * (whack will not allow nexthop to be elided in RW case.)
	 */
	default_end(&d->spd.this, &d->spd.that.host_addr);
	d->spd.next = NULL;
	d->spd.reqid = gen_reqid();

	/* set internal fields */
	d->ac_next = connections;
	connections = d;
	d->spd.routing = RT_UNROUTED;
	d->newest_isakmp_sa = SOS_NOBODY;
	d->newest_ipsec_sa = SOS_NOBODY;
	d->spd.eroute_owner = SOS_NOBODY;

	/* reset log file info */
	d->log_file_name = NULL;
	d->log_file = NULL;
	d->log_file_err = FALSE;

	connect_to_host_pair(d);

	if (sameaddr(&d->spd.that.host_addr, &d->spd.this.host_nexthop))
	{
		d->spd.this.host_nexthop = *him;
	}
	return d;
}

connection_t *rw_instantiate(connection_t *c, const ip_address *him,
							 u_int16_t his_port, const ip_subnet *his_net,
							 identification_t *his_id)
{
	connection_t *d = instantiate(c, him, his_port, his_id);

	if (d && his_net && is_virtual_connection(c))
	{
		d->spd.that.client = *his_net;
		d->spd.that.virt = NULL;
		if (subnetishost(his_net) && addrinsubnet(him, his_net))
			d->spd.that.has_client = FALSE;
	}

	if (d->policy & POLICY_OPPO)
	{
		/* This must be before we know the client addresses.
		 * Fill in one that is impossible.  This prevents anyone else from
		 * trying to use this connection to get to a particular client
		 */
		d->spd.that.client = *aftoinfo(subnettypeof(&d->spd.that.client))->none;
	}
	DBG(DBG_CONTROL
		, DBG_log("instantiated \"%s\" for %s" , d->name, ip_str(him)));
	return d;
}

#ifdef ADNS

connection_t *oppo_instantiate(connection_t *c, const ip_address *him,
							   identification_t *his_id, struct gw_info *gw,
							   const ip_address *our_client USED_BY_DEBUG,
							   const ip_address *peer_client)
{
	connection_t *d = instantiate(c, him, 0, his_id);

	passert(d->spd.next == NULL);

	/* fill in our client side */
	if (d->spd.this.has_client)
	{
		/* there was a client in the abstract connection
		 * so we demand that the required client is within that subnet.
		 */
		passert(addrinsubnet(our_client, &d->spd.this.client));
		happy(addrtosubnet(our_client, &d->spd.this.client));
		/* opportunistic connections do not use port selectors */
		setportof(0, &d->spd.this.client.addr);
	}
	else
	{
		/* there was no client in the abstract connection
		 * so we demand that the required client be the host
		 */
		passert(sameaddr(our_client, &d->spd.this.host_addr));
	}

	/* fill in peer's client side.
	 * If the client is the peer, excise the client from the connection.
	 */
	passert((d->policy & POLICY_OPPO)
		&& addrinsubnet(peer_client, &d->spd.that.client));
	happy(addrtosubnet(peer_client, &d->spd.that.client));
	/* opportunistic connections do not use port selectors */
	setportof(0, &d->spd.that.client.addr);

	if (sameaddr(peer_client, &d->spd.that.host_addr))
		d->spd.that.has_client = FALSE;

	passert(d->gw_info == NULL);
	gw_addref(gw);
	d->gw_info = gw;

	/* Adjust routing if something is eclipsing c.
	 * It must be a %hold for us (hard to passert this).
	 * If there was another instance eclipsing, we'd be using it.
	 */
	if (c->spd.routing == RT_ROUTED_ECLIPSED)
		d->spd.routing = RT_ROUTED_PROSPECTIVE;

	/* Remember if the template is routed:
	 * if so, this instance applies for initiation
	 * even if it is created for responding.
	 */
	if (routed(c->spd.routing))
		d->instance_initiation_ok = TRUE;

	DBG(DBG_CONTROL,
		char topo[BUF_LEN];

		(void) format_connection(topo, sizeof(topo), d, &d->spd);
		DBG_log("instantiated \"%s\": %s", d->name, topo);
	);
	return d;
}

#endif /* ADNS */

/* priority formatting */
void fmt_policy_prio(policy_prio_t pp, char buf[POLICY_PRIO_BUF])
{
	if (pp == BOTTOM_PRIO)
	{
		snprintf(buf, POLICY_PRIO_BUF, "0");
	}
	else
	{
		snprintf(buf, POLICY_PRIO_BUF, "%lu,%lu"
			, pp>>16, (pp & ~(~(policy_prio_t)0 << 16)) >> 8);
	}
}

/* Format any information needed to identify an instance of a connection.
 * Fills any needed information into buf which MUST be big enough.
 * Road Warrior: peer's IP address
 * Opportunistic: [" " myclient "==="] " ..." peer ["===" hisclient] '\0'
 */
static size_t fmt_client(const ip_subnet *client, const ip_address *gw,
						 const char *prefix, char buf[ADDRTOT_BUF])
{
	if (subnetisaddr(client, gw))
	{
		buf[0] = '\0';  /* compact denotation for "self" */
	}
	else
	{
		char *ap;

		strcpy(buf, prefix);
		ap = buf + strlen(prefix);
		if (subnetisnone(client))
			strcpy(ap, "?");    /* unknown */
		else
			subnettot(client, 0, ap, SUBNETTOT_BUF);
	}
	return strlen(buf);
}

void fmt_conn_instance(const connection_t *c, char buf[CONN_INST_BUF])
{
	char *p = buf;

	*p = '\0';

	if (c->kind == CK_INSTANCE)
	{
		if (c->instance_serial != 0)
		{
			snprintf(p, CONN_INST_BUF, "[%lu]", c->instance_serial);
			p += strlen(p);
		}

		if (c->policy & POLICY_OPPO)
		{
			size_t w = fmt_client(&c->spd.this.client, &c->spd.this.host_addr, " ", p);

			p += w;

			strcpy(p, w == 0? " ..." : "=== ...");
			p += strlen(p);

			addrtot(&c->spd.that.host_addr, 0, p, ADDRTOT_BUF);
			p += strlen(p);

			(void) fmt_client(&c->spd.that.client, &c->spd.that.host_addr, "===", p);
		}
		else
		{
			*p++ = ' ';
			addrtot(&c->spd.that.host_addr, 0, p, ADDRTOT_BUF);
#
			if (c->spd.that.host_port != pluto_port)
			{
				p += strlen(p);
				sprintf(p, ":%d", c->spd.that.host_port);
			}
		}
	}
}

/* Find an existing connection for a trapped outbound packet.
 * This is attempted before we bother with gateway discovery.
 *   + this connection is routed or instance_of_routed_template
 *     (i.e. approved for on-demand)
 *   + this subnet contains our_client (or we are our_client)
 *   + that subnet contains peer_client (or peer is peer_client)
 *   + don't care about Phase 1 IDs (we don't know)
 * Note: result may still need to be instantiated.
 * The winner has the highest policy priority.
 *
 * If there are several with that priority, we give preference to
 * the first one that is an instance.
 *
 * See also build_outgoing_opportunistic_connection.
 */
connection_t *find_connection_for_clients(struct spd_route **srp,
										  const ip_address *our_client,
										  const ip_address *peer_client,
										  int transport_proto)
{
	connection_t *c = connections, *best = NULL;
	policy_prio_t best_prio = BOTTOM_PRIO;
	struct spd_route *sr;
	struct spd_route *best_sr = NULL;
	int our_port  = ntohs(portof(our_client));
	int peer_port = ntohs(portof(peer_client));

	passert(!isanyaddr(our_client) && !isanyaddr(peer_client));
#ifdef DEBUG
	if (DBGP(DBG_CONTROL))
	{
		char ocb[ADDRTOT_BUF], pcb[ADDRTOT_BUF];

		addrtot(our_client, 0, ocb, sizeof(ocb));
		addrtot(peer_client, 0, pcb, sizeof(pcb));
		DBG_log("find_connection: "
				"looking for policy for connection: %s:%d/%d -> %s:%d/%d"
				, ocb, transport_proto, our_port, pcb, transport_proto, peer_port);
	}
#endif /* DEBUG */

	for (c = connections; c != NULL; c = c->ac_next)
	{
		if (c->kind == CK_GROUP)
		{
			continue;
		}

		for (sr = &c->spd; best!=c && sr; sr = sr->next)
		{
			if ((routed(sr->routing) || c->instance_initiation_ok)
			&& addrinsubnet(our_client, &sr->this.client)
			&& addrinsubnet(peer_client, &sr->that.client)
			&& addrinsubnet(peer_client, &sr->that.client)
			&& (!sr->this.protocol || transport_proto == sr->this.protocol)
			&& (!sr->this.port || our_port == sr->this.port)
			&& (!sr->that.port || peer_port == sr->that.port))
			{
				char cib[CONN_INST_BUF];
				char cib2[CONN_INST_BUF];

				policy_prio_t prio = 8 * (c->prio + (c->kind == CK_INSTANCE))
								   + 2 * (sr->this.port == our_port)
								   + 2 * (sr->that.port == peer_port)
								   +     (sr->this.protocol == transport_proto);

#ifdef DEBUG
				if (DBGP(DBG_CONTROL|DBG_CONTROLMORE))
				{
					char c_ocb[SUBNETTOT_BUF], c_pcb[SUBNETTOT_BUF];

					subnettot(&c->spd.this.client, 0, c_ocb, sizeof(c_ocb));
					subnettot(&c->spd.that.client, 0, c_pcb, sizeof(c_pcb));
					DBG_log("find_connection: conn \"%s\"%s has compatible peers: %s->%s [pri: %ld]"
							, c->name
							, (fmt_conn_instance(c, cib), cib)
							, c_ocb, c_pcb, prio);
				}
#endif /* DEBUG */

				if (best == NULL)
				{
					best = c;
					best_sr = sr;
					best_prio = prio;
				}

				DBG(DBG_CONTROLMORE,
					DBG_log("find_connection: "
							"comparing best \"%s\"%s [pri:%ld]{%p} (child %s) to \"%s\"%s [pri:%ld]{%p} (child %s)"
							, best->name
							, (fmt_conn_instance(best, cib), cib)
							, best_prio
							, best
							, (best->policy_next ? best->policy_next->name : "none")
							, c->name
							, (fmt_conn_instance(c, cib2), cib2)
							, prio
							, c
							, (c->policy_next ? c->policy_next->name : "none")));

				if (prio > best_prio)
				{
					best = c;
					best_sr = sr;
					best_prio = prio;
				}
			}
		}
	}

	if (best && NEVER_NEGOTIATE(best->policy))
	{
		best = NULL;
	}
	if (srp && best)
	{
		*srp = best_sr;
	}

#ifdef DEBUG
	if (DBGP(DBG_CONTROL))
	{
		if (best)
		{
			char cib[CONN_INST_BUF];
			DBG_log("find_connection: concluding with \"%s\"%s [pri:%ld]{%p} kind=%s"
					, best->name
					, (fmt_conn_instance(best, cib), cib)
					, best_prio
					, best
					, enum_name(&connection_kind_names, best->kind));
		} else {
			DBG_log("find_connection: concluding with empty");
		}
	}
#endif /* DEBUG */

	return best;
}

#ifdef ADNS

/* Find and instantiate a connection for an outgoing Opportunistic connection.
 * We've already discovered its gateway.
 * We look for a the connection such that:
 *   + this is one of our interfaces
 *   + this subnet contains our_client (or we are our_client)
 *     (we will specialize the client).  We prefer the smallest such subnet.
 *   + that subnet contains peer_clent (we will specialize the client).
 *     We prefer the smallest such subnet.
 *   + is opportunistic
 *   + that peer is NO_IP
 *   + don't care about Phase 1 IDs (probably should be default)
 * We could look for a connection that already had the desired peer
 * (rather than NO_IP) specified, but it doesn't seem worth the
 * bother.
 *
 * We look for the routed policy applying to the narrowest subnets.
 * We only succeed if we find such a policy AND it is satisfactory.
 *
 * The body of the inner loop is a lot like that in
 * find_connection_for_clients.  In this case, we know the gateways
 * that we need to instantiate an opportunistic connection.
 */
connection_t *build_outgoing_opportunistic_connection(struct gw_info *gw,
											const ip_address *our_client,
											const ip_address *peer_client)
{
	struct iface *p;
	connection_t *best = NULL;
	struct spd_route *sr, *bestsr;
	char ocb[ADDRTOT_BUF], pcb[ADDRTOT_BUF];

	addrtot(our_client, 0, ocb, sizeof(ocb));
	addrtot(peer_client, 0, pcb, sizeof(pcb));

	/* for each of our addresses... */
	for (p = interfaces; p != NULL; p = p->next)
	{
		/* go through those connections with our address and NO_IP as hosts
		 * We cannot know what port the peer would use, so we assume
		 * that it is pluto_port (makes debugging easier).
		 */
		connection_t *c = find_host_pair_connections(&p->addr, pluto_port,
										 (ip_address *)NULL, pluto_port);

		for (; c != NULL; c = c->hp_next)
		{
			DBG(DBG_OPPO,
				DBG_log("checking %s", c->name));
			if (c->kind == CK_GROUP)
			{
				continue;
			}

			for (sr = &c->spd; best!=c && sr; sr = sr->next)
			{
				if (routed(sr->routing)
				&& addrinsubnet(our_client, &sr->this.client)
				&& addrinsubnet(peer_client, &sr->that.client))
				{
					if (best == NULL)
					{
						best = c;
						break;
					}

					DBG(DBG_OPPO,
						DBG_log("comparing best %s to %s"
								, best->name, c->name));

					for (bestsr = &best->spd; best!=c && bestsr; bestsr=bestsr->next)
					{
						if (!subnetinsubnet(&bestsr->this.client, &sr->this.client)
						|| (samesubnet(&bestsr->this.client, &sr->this.client)
							 && !subnetinsubnet(&bestsr->that.client
												, &sr->that.client)))
						{
							best = c;
						}
					}
				}
			}
		}
	}

	if (best == NULL || NEVER_NEGOTIATE(best->policy) ||
	   (best->policy & POLICY_OPPO) == LEMPTY || best->kind != CK_TEMPLATE)
	{
		return NULL;
	}
	else
	{
		chunk_t encoding = gw->gw_id->get_encoding(gw->gw_id);
		id_type_t type   = gw->gw_id->get_type(gw->gw_id);
		ip_address ip_addr;

		initaddr(encoding.ptr, encoding.len,
				(type == ID_IPV4_ADDR) ? AF_INET : AF_INET6, &ip_addr);

		return oppo_instantiate(best, &ip_addr, NULL, gw, our_client, peer_client);
	}
}

#endif /* ADNS */

bool orient(connection_t *c)
{
	struct spd_route *sr;

	if (!oriented(*c))
	{
		struct iface *p;

		for (sr = &c->spd; sr; sr = sr->next)
		{
			/* Note: this loop does not stop when it finds a match:
			 * it continues checking to catch any ambiguity.
			 */
			for (p = interfaces; p != NULL; p = p->next)
			{
				if (p->ike_float)
				{
					continue;
				}

				for (;;)
				{
					/* check if this interface matches this end */
					if (sameaddr(&sr->this.host_addr, &p->addr)
						&& sr->this.host_port == pluto_port)
					{
						if (oriented(*c))
						{
							if (c->interface == p)
								loglog(RC_LOG_SERIOUS
									   , "both sides of \"%s\" are our interface %s!"
									   , c->name, p->rname);
							else
								loglog(RC_LOG_SERIOUS, "two interfaces match \"%s\" (%s, %s)"
									   , c->name, c->interface->rname, p->rname);
							c->interface = NULL;        /* withdraw orientation */
							return FALSE;
						}
						c->interface = p;
					}

					/* done with this interface if it doesn't match that end */
					if (!(sameaddr(&sr->that.host_addr, &p->addr)
						&& sr->that.host_port == pluto_port))
						break;

					/* swap ends and try again.
					 * It is a little tricky to see that this loop will stop.
					 * Only continue if the far side matches.
					 * If both sides match, there is an error-out.
					 */
					{
						struct end t = sr->this;

						sr->this = sr->that;
						sr->that = t;
					}
				}
			}
		}
	}
	return oriented(*c);
}

void initiate_connection(const char *name, int whackfd)
{
	connection_t *c = con_by_name(name, TRUE);

	if (c && c->ikev1)
	{
		set_cur_connection(c);
		if (!oriented(*c))
		{
			loglog(RC_ORIENT, "we have no ipsecN interface for either end of this connection");
		}
		else if (NEVER_NEGOTIATE(c->policy))
		{
			loglog(RC_INITSHUNT
				, "cannot initiate an authby=never connection");
		}
		else if (c->kind != CK_PERMANENT && !c->spd.that.allow_any)
		{
			if (isanyaddr(&c->spd.that.host_addr))
				loglog(RC_NOPEERIP, "cannot initiate connection without knowing peer IP address");
			else
				loglog(RC_WILDCARD, "cannot initiate connection with ID wildcards");
		}
		else
		{
			/* do we have to prompt for a PIN code? */
			if (c->spd.this.sc && !c->spd.this.sc->valid && whackfd != NULL_FD)
			{
				scx_get_pin(c->spd.this.sc, whackfd);
			}
			if (c->spd.this.sc && !c->spd.this.sc->valid)
			{
				loglog(RC_NOVALIDPIN, "cannot initiate connection without valid PIN");
			}
			else
			{

				if (c->spd.that.allow_any)
				{
					c = instantiate(c, &c->spd.that.host_addr,
									c->spd.that.host_port, c->spd.that.id);
				}

				/* We will only request an IPsec SA if policy isn't empty
				 * (ignoring Main Mode items).
				 * This is a fudge, but not yet important.
				 * If we are to proceed asynchronously, whackfd will be NULL_FD.
				 */
				c->policy |= POLICY_UP;
				ipsecdoi_initiate(whackfd, c, c->policy, 1, SOS_NOBODY);
				whackfd = NULL_FD;      /* protect from close */
			}
		}
		reset_cur_connection();
	}
	close_any(whackfd);
}

/* (Possibly) Opportunistic Initiation:
 * Knowing clients (single IP addresses), try to build an tunnel.
 * This may involve discovering a gateway and instantiating an
 * Opportunistic connection.  Called when a packet is caught by
 * a %trap, or when whack --oppohere --oppothere is used.
 * It may turn out that an existing or non-opporunistic connnection
 * can handle the traffic.
 *
 * Most of the code will be restarted if an ADNS request is made
 * to discover the gateway.  The only difference between the first
 * and second entry is whether gateways_from_dns is NULL or not.
 *      initiate_opportunistic: initial entrypoint
 *      continue_oppo: where we pickup when ADNS result arrives
 *      initiate_opportunistic_body: main body shared by above routines
 *      cannot_oppo: a helper function to log a diagnostic
 * This structure repeats a lot of code when the ADNS result arrives.
 * This seems like a waste, but anything learned the first time through
 * may no longer be true!
 *
 * After the first IKE message is sent, the regular state machinery
 * carries negotiation forward.
 */

enum find_oppo_step {
	fos_start,
	fos_myid_ip_txt,
	fos_myid_hostname_txt,
	fos_myid_ip_key,
	fos_myid_hostname_key,
	fos_our_client,
	fos_our_txt,
#ifdef USE_KEYRR
	fos_our_key,
#endif /* USE_KEYRR */
	fos_his_client,
	fos_done
};

#ifdef DEBUG
static const char *const oppo_step_name[] = {
	"fos_start",
	"fos_myid_ip_txt",
	"fos_myid_hostname_txt",
	"fos_myid_ip_key",
	"fos_myid_hostname_key",
	"fos_our_client",
	"fos_our_txt",
#ifdef USE_KEYRR
	"fos_our_key",
#endif /* USE_KEYRR */
	"fos_his_client",
	"fos_done"
};
#endif /* DEBUG */

struct find_oppo_bundle {
	enum find_oppo_step step;
	err_t want;
	bool failure_ok;            /* if true, continue_oppo should not die on DNS failure */
	ip_address our_client;      /* not pointer! */
	ip_address peer_client;
	int transport_proto;
	bool held;
	policy_prio_t policy_prio;
	ipsec_spi_t failure_shunt;  /* in host order!  0 for delete. */
	int whackfd;
};

struct find_oppo_continuation {
	struct adns_continuation ac;        /* common prefix */
	struct find_oppo_bundle b;
};

static void cannot_oppo(connection_t *c, struct find_oppo_bundle *b, err_t ugh)
{
	char pcb[ADDRTOT_BUF];
	char ocb[ADDRTOT_BUF];

	addrtot(&b->peer_client, 0, pcb, sizeof(pcb));
	addrtot(&b->our_client, 0, ocb, sizeof(ocb));

	DBG(DBG_DNS | DBG_OPPO, DBG_log("Can't Opportunistically initiate for %s to %s: %s"
		, ocb, pcb, ugh));

	whack_log(RC_OPPOFAILURE
		, "Can't Opportunistically initiate for %s to %s: %s"
		, ocb, pcb, ugh);

	if (c && c->policy_next)
	{
		/* there is some policy that comes afterwards */
		struct spd_route *shunt_spd;
		connection_t *nc = c->policy_next;
		struct state *st;

		passert(c->kind == CK_TEMPLATE);
		passert(c->policy_next->kind == CK_PERMANENT);

		DBG(DBG_OPPO, DBG_log("OE failed for %s to %s, but %s overrides shunt"
							  , ocb, pcb, c->policy_next->name));

		/*
		 * okay, here we need add to the "next" policy, which is ought
		 * to be an instance.
		 * We will add another entry to the spd_route list for the specific
		 * situation that we have.
		 */

		shunt_spd = clone_thing(nc->spd);

		shunt_spd->next = nc->spd.next;
		nc->spd.next = shunt_spd;

		happy(addrtosubnet(&b->peer_client, &shunt_spd->that.client));

		if (sameaddr(&b->peer_client, &shunt_spd->that.host_addr))
			shunt_spd->that.has_client = FALSE;

		/*
		 * override the tunnel destination with the one from the secondaried
		 * policy
		 */
		shunt_spd->that.host_addr = nc->spd.that.host_addr;

		/* now, lookup the state, and poke it up.
		 */

		st = state_with_serialno(nc->newest_ipsec_sa);

		/* XXX what to do if the IPSEC SA has died? */
		passert(st != NULL);

		/* link the new connection instance to the state's list of
		 * connections
		 */

		DBG(DBG_OPPO, DBG_log("installing state: %ld for %s to %s"
							  , nc->newest_ipsec_sa
							  , ocb, pcb));

#ifdef DEBUG
		if (DBGP(DBG_OPPO | DBG_CONTROLMORE))
		{
			char state_buf[LOG_WIDTH];
			char state_buf2[LOG_WIDTH];
			time_t n = now();

			fmt_state(FALSE, st, n
					  , state_buf, sizeof(state_buf)
					  , state_buf2, sizeof(state_buf2));
			DBG_log("cannot_oppo, failure SA1: %s", state_buf);
			DBG_log("cannot_oppo, failure SA2: %s", state_buf2);
		}
#endif /* DEBUG */

		if (!route_and_eroute(c, shunt_spd, st))
		{
			whack_log(RC_OPPOFAILURE
					  , "failed to instantiate shunt policy %s for %s to %s"
					  , c->name
					  , ocb, pcb);
		}
		return;
	}
}

static void initiate_opportunistic_body(struct find_oppo_bundle *b
	, struct adns_continuation *ac, err_t ac_ugh);      /* forward */

void initiate_opportunistic(const ip_address *our_client,
							const ip_address *peer_client, int transport_proto,
							bool held, int whackfd)
{
	struct find_oppo_bundle b;

	b.want = (whackfd == NULL_FD ? "whack" : "acquire");
	b.failure_ok = FALSE;
	b.our_client = *our_client;
	b.peer_client = *peer_client;
	b.transport_proto = transport_proto;
	b.held = held;
	b.policy_prio = BOTTOM_PRIO;
	b.failure_shunt = 0;
	b.whackfd = whackfd;
	b.step = fos_start;
	initiate_opportunistic_body(&b, NULL, NULL);
}

#ifdef ADNS

static void continue_oppo(struct adns_continuation *acr, err_t ugh)
{
	struct find_oppo_continuation *cr = (void *)acr;    /* inherit, damn you! */
	connection_t *c;
	bool was_held = cr->b.held;
	int whackfd = cr->b.whackfd;

	/* note: cr->id has no resources; cr->sgw_id is ID_ANY:
	 * neither need freeing.
	 */
	whack_log_fd = whackfd;

#ifdef DEBUG
	/* if we're going to ignore the error, at least note it in debugging log */
	if (cr->b.failure_ok && ugh)
	{
		DBG(DBG_CONTROL | DBG_DNS,
			{
				char ocb[ADDRTOT_BUF];
				char pcb[ADDRTOT_BUF];

				addrtot(&cr->b.our_client, 0, ocb, sizeof(ocb));
				addrtot(&cr->b.peer_client, 0, pcb, sizeof(pcb));
				DBG_log("continuing from failed DNS lookup for %s, %s to %s: %s"
					, cr->b.want, ocb, pcb, ugh);
			});
	}
#endif

	if (!cr->b.failure_ok && ugh)
	{
		c = find_connection_for_clients(NULL, &cr->b.our_client, &cr->b.peer_client
			, cr->b.transport_proto);
		cannot_oppo(c, &cr->b
					, builddiag("%s: %s", cr->b.want, ugh));
	}
	else if (was_held && !cr->b.held)
	{
		/* was_held indicates we were started due to a %trap firing
		 * (as opposed to a "whack --oppohere --oppothere").
		 * Since the %hold has gone, we can assume that somebody else
		 * has beaten us to the punch.  We can go home.  But lets log it.
		 */
		char ocb[ADDRTOT_BUF];
		char pcb[ADDRTOT_BUF];

		addrtot(&cr->b.our_client, 0, ocb, sizeof(ocb));
		addrtot(&cr->b.peer_client, 0, pcb, sizeof(pcb));

		loglog(RC_COMMENT
			, "%%hold otherwise handled during DNS lookup for Opportunistic Initiation for %s to %s"
			, ocb, pcb);
	}
	else
	{
		initiate_opportunistic_body(&cr->b, &cr->ac, ugh);
		whackfd = NULL_FD;      /* was handed off */
	}

	whack_log_fd = NULL_FD;
	close_any(whackfd);
}

#endif /* ADNS */

#ifdef USE_KEYRR
static err_t check_key_recs(enum myid_state try_state, const connection_t *c,
							struct adns_continuation *ac)
{
	/* Check if KEY lookup yielded good results.
	 * Looking up based on our ID.  Used if
	 * client is ourself, or if TXT had no public key.
	 * Note: if c is different this time, there is
	 * a chance that we did the wrong query.
	 * If so, treat as a kind of failure.
	 */
	enum myid_state old_myid_state = myid_state;
	private_key_t *private;
	err_t ugh = NULL;

	myid_state = try_state;

	if (old_myid_state != myid_state && old_myid_state == MYID_SPECIFIED)
	{
		ugh = "%myid was specified while we were guessing";
	}
	else if ((private = get_private_key(c)) == NULL)
	{
		ugh = "we don't know our own RSA key";
	}
	else if (!same_id(&ac->id, &c->spd.this.id))
	{
		ugh = "our ID changed underfoot";
	}
	else
	{
		/* Similar to code in RSA_check_signature
		 * for checking the other side.
		 */
		pubkey_list_t *kr;

		ugh = "no KEY RR found for us";
		for (kr = ac->keys_from_dns; kr != NULL; kr = kr->next)
		{
			ugh = "all our KEY RRs have the wrong public key";
			if (kr->key->alg == PUBKEY_ALG_RSA
			&& private->belongs_to(private, &kr->key->public_key))
			{
				ugh = NULL;     /* good! */
				break;
			}
		}
	}
	if (ugh)
	{
		myid_state = old_myid_state;
	}
	return ugh;
}
#endif /* USE_KEYRR */

#ifdef ADNS

static err_t check_txt_recs(enum myid_state try_state, const connection_t *c,
							struct adns_continuation *ac)
{
	/* Check if TXT lookup yielded good results.
	 * Looking up based on our ID.  Used if
	 * client is ourself, or if TXT had no public key.
	 * Note: if c is different this time, there is
	 * a chance that we did the wrong query.
	 * If so, treat as a kind of failure.
	 */
	enum myid_state old_myid_state = myid_state;
	private_key_t *private;
	err_t ugh = NULL;

	myid_state = try_state;

	if (old_myid_state != myid_state
	&& old_myid_state == MYID_SPECIFIED)
	{
		ugh = "%myid was specified while we were guessing";
	}
	else if ((private = get_private_key(c)) == NULL)
	{
		ugh = "we don't know our own RSA key";
	}
	else if (!ac->id->equals(ac->id, c->spd.this.id))
	{
		ugh = "our ID changed underfoot";
	}
	else
	{
		/* Similar to code in RSA_check_signature
		 * for checking the other side.
		 */
		struct gw_info *gwp;

		ugh = "no TXT RR found for us";
		for (gwp = ac->gateways_from_dns; gwp != NULL; gwp = gwp->next)
		{
			public_key_t *pub_key = gwp->key->public_key;

			ugh = "all our TXT RRs have the wrong public key";
			if (pub_key->get_type(pub_key) == KEY_RSA &&
			    private->belongs_to(private, pub_key))
			{
				ugh = NULL;     /* good! */
				break;
			}
		}
	}
	if (ugh)
	{
		myid_state = old_myid_state;
	}
	return ugh;
}

#endif /* ADNS */


/* note: gateways_from_dns must be NULL iff this is the first call */
static void initiate_opportunistic_body(struct find_oppo_bundle *b,
										struct adns_continuation *ac,
										err_t ac_ugh)
{
	connection_t *c;
	struct spd_route *sr;

	/* What connection shall we use?
	 * First try for one that explicitly handles the clients.
	 */
	DBG(DBG_CONTROL,
		{
			char ours[ADDRTOT_BUF];
			char his[ADDRTOT_BUF];
			int ourport;
			int hisport;

			addrtot(&b->our_client, 0, ours, sizeof(ours));
			addrtot(&b->peer_client, 0, his, sizeof(his));
			ourport = ntohs(portof(&b->our_client));
			hisport = ntohs(portof(&b->peer_client));
			DBG_log("initiate on demand from %s:%d to %s:%d proto=%d state: %s because: %s"
				, ours, ourport, his, hisport, b->transport_proto
				, oppo_step_name[b->step], b->want);
		});
	if (isanyaddr(&b->our_client) || isanyaddr(&b->peer_client))
	{
		cannot_oppo(NULL, b, "impossible IP address");
	}
	else if ((c = find_connection_for_clients(&sr
											  , &b->our_client
											  , &b->peer_client
											  , b->transport_proto)) == NULL)
	{
		/* No connection explicitly handles the clients and there
		 * are no Opportunistic connections -- whine and give up.
		 * The failure policy cannot be gotten from a connection; we pick %pass.
		 */
		cannot_oppo(NULL, b, "no routed Opportunistic template covers this pair");
	}
	else if (c->kind != CK_TEMPLATE)
	{
		/* We've found a connection that can serve.
		 * Do we have to initiate it?
		 * Not if there is currently an IPSEC SA.
		 * But if there is an IPSEC SA, then the kernel would not
		 * have generated the acquire.  So we assume that there isn't one.
		 * This may be redundant if a non-opportunistic
		 * negotiation is already being attempted.
		 */

		/* If we are to proceed asynchronously, b->whackfd will be NULL_FD. */

		if(c->kind == CK_INSTANCE)
		{
			char cib[CONN_INST_BUF];
			/* there is already an instance being negotiated, no nothing */
			DBG(DBG_CONTROL, DBG_log("found existing instance \"%s\"%s, rekeying it"
									 , c->name
									 , (fmt_conn_instance(c, cib), cib)));
			/* XXX-mcr - return; */
		}

		/* otherwise, there is some kind of static conn that can handle
		 * this connection, so we initiate it */

		if (b->held)
		{
			/* what should we do on failure? */
			(void) assign_hold(c, sr, b->transport_proto, &b->our_client, &b->peer_client);
		}
		ipsecdoi_initiate(b->whackfd, c, c->policy, 1, SOS_NOBODY);
		b->whackfd = NULL_FD;   /* protect from close */
	}
#ifdef ADNS
	else
	{
		/* We are handling an opportunistic situation.
		 * This involves several DNS lookup steps that require suspension.
		 * Note: many facts might change while we're suspended.
		 * Here be dragons.
		 *
		 * The first chunk of code handles the result of the previous
		 * DNS query (if any).  It also selects the kind of the next step.
		 * The second chunk initiates the next DNS query (if any).
		 */
		enum find_oppo_step next_step = fos_myid_ip_txt;
		err_t ugh = ac_ugh;
		char mycredentialstr[BUF_LEN];
		char cib[CONN_INST_BUF];

		DBG(DBG_CONTROL, DBG_log("creating new instance from \"%s\"%s",
								 c->name, (fmt_conn_instance(c, cib), cib)));
		snprintf(mycredentialstr, BUF_LEN, "%Y", sr->this.id);

		/* handle any DNS answer; select next step */
		switch (b->step)
		{
		case fos_start:
			/* just starting out: select first query step */
			next_step = fos_myid_ip_txt;
			break;

		case fos_myid_ip_txt:   /* TXT for our default IP address as %myid */
			ugh = check_txt_recs(MYID_IP, c, ac);
			if (ugh)
			{
				/* cannot use our IP as OE identitiy for initiation */
				DBG(DBG_OPPO,
					DBG_log("can not use our IP (%Y:TXT) as identity: %s",
							myids[MYID_IP], ugh));
				if (!logged_myid_ip_txt_warning)
				{
					loglog(RC_LOG_SERIOUS,
							"can not use our IP (%Y:TXT) as identity: %s",
							myids[MYID_IP], ugh);
					logged_myid_ip_txt_warning = TRUE;
				}

				next_step = fos_myid_hostname_txt;
				ugh = NULL;     /* failure can be recovered from */
			}
			else
			{
				/* we can use our IP as OE identity for initiation */
				if (!logged_myid_ip_txt_warning)
				{
					loglog(RC_LOG_SERIOUS,
							"using our IP (%Y:TXT) as identity!",
							myids[MYID_IP]);
					logged_myid_ip_txt_warning = TRUE;
				}

				next_step = fos_our_client;
			}
			break;

		case fos_myid_hostname_txt:     /* TXT for our hostname as %myid */
			ugh = check_txt_recs(MYID_HOSTNAME, c, ac);
			if (ugh)
			{
				/* cannot use our hostname as OE identitiy for initiation */
				DBG(DBG_OPPO,
					DBG_log("can not use our hostname (%Y:TXT) as identity: %s",
							myids[MYID_HOSTNAME], ugh));
				if (!logged_myid_fqdn_txt_warning)
				{
					loglog(RC_LOG_SERIOUS,
							"can not use our hostname (%Y:TXT) as identity: %s",
							myids[MYID_HOSTNAME], ugh);
					logged_myid_fqdn_txt_warning = TRUE;
				}
#ifdef USE_KEYRR
				next_step = fos_myid_ip_key;
				ugh = NULL;     /* failure can be recovered from */
#endif
			}
			else
			{
				/* we can use our hostname as OE identity for initiation */
				if (!logged_myid_fqdn_txt_warning)
				{
					loglog(RC_LOG_SERIOUS,
							"using our hostname (%Y:TXT) as identity!",
							myids[MYID_HOSTNAME]);
					logged_myid_fqdn_txt_warning = TRUE;
				}
				next_step = fos_our_client;
			}
			break;

#ifdef USE_KEYRR
		case fos_myid_ip_key:   /* KEY for our default IP address as %myid */
			ugh = check_key_recs(MYID_IP, c, ac);
			if (ugh)
			{
				/* cannot use our IP as OE identitiy for initiation */
				DBG(DBG_OPPO,
					DBG_log("can not use our IP (%Y:KEY) as identity: %s",
							myids[MYID_IP], ugh));
				if (!logged_myid_ip_key_warning)
				{
					loglog(RC_LOG_SERIOUS,
							"can not use our IP (%Y:KEY) as identity: %s",
							myids[MYID_IP], ugh);
					logged_myid_ip_key_warning = TRUE;
				}

				next_step = fos_myid_hostname_key;
				ugh = NULL;     /* failure can be recovered from */
			}
			else
			{
				/* we can use our IP as OE identity for initiation */
				if (!logged_myid_ip_key_warning)
				{
					loglog(RC_LOG_SERIOUS,
							"using our IP (%Y:KEY) as identity!",
							myids[MYID_IP]);
					logged_myid_ip_key_warning = TRUE;
				}
				next_step = fos_our_client;
			}
			break;

		case fos_myid_hostname_key:     /* KEY for our hostname as %myid */
			ugh = check_key_recs(MYID_HOSTNAME, c, ac);
			if (ugh)
			{
				/* cannot use our IP as OE identitiy for initiation */
				DBG(DBG_OPPO,
					DBG_log("can not use our hostname (%Y:KEY) as identity: %s",
							myids[MYID_HOSTNAME], ugh));
				if (!logged_myid_fqdn_key_warning)
				{
					loglog(RC_LOG_SERIOUS,
							"can not use our hostname (%Y:KEY) as identity: %s",
							myids[MYID_HOSTNAME], ugh);
					logged_myid_fqdn_key_warning = TRUE;
				}
				next_step = fos_myid_hostname_key;
				ugh = NULL;     /* failure can be recovered from */
			}
			else
			{
				/* we can use our IP as OE identity for initiation */
				if (!logged_myid_fqdn_key_warning)
				{
					loglog(RC_LOG_SERIOUS,
							"using our hostname (%Y:KEY) as identity!",
							myids[MYID_HOSTNAME]);
					logged_myid_fqdn_key_warning = TRUE;
				}
				next_step = fos_our_client;
			}
			break;
#endif

		case fos_our_client:    /* TXT for our client */
			{
				/* Our client is not us: we must check the TXT records.
				 * Note: if c is different this time, there is
				 * a chance that we did the wrong query.
				 * If so, treat as a kind of failure.
				 */
				private_key_t *private = get_private_key(c);

				next_step = fos_his_client;     /* normal situation */

				if (private == NULL)
				{
					ugh = "we don't know our own RSA key";
				}
				else if (sameaddr(&sr->this.host_addr, &b->our_client))
				{
					/* this wasn't true when we started -- bail */
					ugh = "our IP address changed underfoot";
				}
				else if (!ac->sgw_id->equals(ac->sgw_id, sr->this.id))
				{
					/* this wasn't true when we started -- bail */
					ugh = "our ID changed underfoot";
				}
				else
				{
					/* Similar to code in quick_inI1_outR1_tail
					 * for checking the other side.
					 */
					struct gw_info *gwp;

					ugh = "no TXT RR for our client delegates us";
					for (gwp = ac->gateways_from_dns; gwp != NULL; gwp = gwp->next)
					{
						ugh = "TXT RR for our client has wrong key";
						/* If there is a key from the TXT record,
						 * we count it as a win if we match the key.
						 * If there was no key, we have a tentative win:
						 * we need to check our KEY record to be sure.
						 */
						if (!gwp->gw_key_present)
						{
							/* Success, but the TXT had no key
							 * so we must check our our own KEY records.
							 */
							next_step = fos_our_txt;
							ugh = NULL; /* good! */
							break;
						}
						if (private->belongs_to(private, gwp->key->public_key))
						{
							ugh = NULL; /* good! */
							break;
						}
					}
				}
			}
			break;

		case fos_our_txt:       /* TXT for us */
			{
				/* Check if TXT lookup yielded good results.
				 * Looking up based on our ID.  Used if
				 * client is ourself, or if TXT had no public key.
				 * Note: if c is different this time, there is
				 * a chance that we did the wrong query.
				 * If so, treat as a kind of failure.
				 */
				private_key_t *private = get_private_key(c);

				next_step = fos_his_client;     /* unless we decide to look for KEY RR */

				if (private == NULL)
				{
					ugh = "we don't know our own RSA key";
				}
				else if (!ac->id->equals(ac->id, c->spd.this.id))
				{
					ugh = "our ID changed underfoot";
				}
				else
				{
					/* Similar to code in RSA_check_signature
					 * for checking the other side.
					 */
					struct gw_info *gwp;

					ugh = "no TXT RR for us";
					for (gwp = ac->gateways_from_dns; gwp != NULL; gwp = gwp->next)
					{
						ugh = "TXT RR for us has wrong key";
						if (gwp->gw_key_present &&
							private->belongs_to(private, gwp->key->public_key))
						{
							DBG(DBG_CONTROL,
								DBG_log("initiate on demand found TXT with right public key at: %s"
										, mycredentialstr));
							ugh = NULL;
							break;
						}
					}
#ifdef USE_KEYRR
					if (ugh)
					{
						/* if no TXT with right key, try KEY */
						DBG(DBG_CONTROL,
							DBG_log("will try for KEY RR since initiate on demand found %s: %s"
									, ugh, mycredentialstr));
						next_step = fos_our_key;
						ugh = NULL;
					}
#endif
				}
			}
			break;

#ifdef USE_KEYRR
		case fos_our_key:       /* KEY for us */
			{
				/* Check if KEY lookup yielded good results.
				 * Looking up based on our ID.  Used if
				 * client is ourself, or if TXT had no public key.
				 * Note: if c is different this time, there is
				 * a chance that we did the wrong query.
				 * If so, treat as a kind of failure.
				 */
				private_key_t *private = get_private_key(c);

				next_step = fos_his_client;     /* always */

				if (private == NULL)
				{
					ugh = "we don't know our own RSA key";
				}
				else if (!same_id(&ac->id, &c->spd.this.id))
				{
					ugh = "our ID changed underfoot";
				}
				else
				{
					/* Similar to code in RSA_check_signature
					 * for checking the other side.
					 */
					pubkey_list_t *kr;

					ugh = "no KEY RR found for us (and no good TXT RR)";
					for (kr = ac->keys_from_dns; kr != NULL; kr = kr->next)
					{
						ugh = "all our KEY RRs have the wrong public key (and no good TXT RR)";
						if (kr->key->alg == PUBKEY_ALG_RSA
						&& private->belongs_to(private, kr->key->public_key))
						{
							/* do this only once a day */
							if (!logged_txt_warning)
							{
								loglog(RC_LOG_SERIOUS
									   , "found KEY RR but not TXT RR for %s. See http://www.freeswan.org/err/txt-change.html."
									   , mycredentialstr);
								logged_txt_warning = TRUE;
							}
							ugh = NULL; /* good! */
							break;
						}
					}
				}
			}
			break;
#endif /* USE_KEYRR */

		case fos_his_client:    /* TXT for his client */
			{
				/* We've finished last DNS queries: TXT for his client.
				 * Using the information, try to instantiate a connection
				 * and start negotiating.
				 * We now know the peer.  The chosing of "c" ignored this,
				 * so we will disregard its current value.
				 * !!! We need to randomize the entry in gw that we choose.
				 */
				next_step = fos_done;   /* no more queries */

				c = build_outgoing_opportunistic_connection(ac->gateways_from_dns
															, &b->our_client
															, &b->peer_client);

				if (c == NULL)
				{
					/* We cannot seem to instantiate a suitable connection:
					 * complain clearly.
					 */
					char ocb[ADDRTOT_BUF], pcb[ADDRTOT_BUF];

					addrtot(&b->our_client, 0, ocb, sizeof(ocb));
					addrtot(&b->peer_client, 0, pcb, sizeof(pcb));
					loglog(RC_OPPOFAILURE,
							"no suitable connection for opportunism "
							"between %s and %s with %Y as peer",
							 ocb, pcb, ac->gateways_from_dns->gw_id);
				}
				else
				{
					/* If we are to proceed asynchronously, b->whackfd will be NULL_FD. */
					passert(c->kind == CK_INSTANCE);
					passert(c->gw_info != NULL);
					passert(HAS_IPSEC_POLICY(c->policy));
					passert(LHAS(LELEM(RT_UNROUTED) | LELEM(RT_ROUTED_PROSPECTIVE), c->spd.routing));
					if (b->held)
					{
						/* what should we do on failure? */
						(void) assign_hold(c, &c->spd
										   , b->transport_proto
										   , &b->our_client, &b->peer_client);
					}
					c->gw_info->key->last_tried_time = now();
					ipsecdoi_initiate(b->whackfd, c, c->policy, 1, SOS_NOBODY);
					b->whackfd = NULL_FD;       /* protect from close */
				}
			}
			break;

		default:
			bad_case(b->step);
		}

		/* the second chunk: initiate the next DNS query (if any) */
		DBG(DBG_CONTROL,
		{
			char ours[ADDRTOT_BUF];
			char his[ADDRTOT_BUF];

			addrtot(&b->our_client, 0, ours, sizeof(ours));
			addrtot(&b->peer_client, 0, his, sizeof(his));
			DBG_log("initiate on demand from %s to %s new state: %s with ugh: %s"
					, ours, his, oppo_step_name[b->step], ugh ? ugh : "ok");
		});

		if (ugh)
		{
			b->policy_prio = c->prio;
			b->failure_shunt = shunt_policy_spi(c, FALSE);
			cannot_oppo(c, b, ugh);
		}
		else if (next_step == fos_done)
		{
			/* nothing to do */
		}
		else
		{
			/* set up the next query */
			struct find_oppo_continuation *cr = malloc_thing(struct find_oppo_continuation);
			identification_t *id;

			b->policy_prio = c->prio;
			b->failure_shunt = shunt_policy_spi(c, FALSE);
			cr->b = *b; /* copy; start hand off of whackfd */
			cr->b.failure_ok = FALSE;
			cr->b.step = next_step;

			for (sr = &c->spd
			; sr!=NULL && !sameaddr(&sr->this.host_addr, &b->our_client)
			; sr = sr->next)
				;

			if (sr == NULL)
				sr = &c->spd;

			/* If a %hold shunt has replaced the eroute for this template,
			 * record this fact.
			 */
			if (b->held
			&& sr->routing == RT_ROUTED_PROSPECTIVE && eclipsable(sr))
			{
				sr->routing = RT_ROUTED_ECLIPSED;
				eclipse_count++;
			}

			/* Switch to issue next query.
			 * A case may turn out to be unnecessary.  If so, it falls
			 * through to the next case.
			 * Figuring out what %myid can stand for must be done before
			 * our client credentials are looked up: we must know what
			 * the client credentials may use to identify us.
			 * On the other hand, our own credentials should be looked
			 * up after our clients in case our credentials are not
			 * needed at all.
			 * XXX this is a wasted effort if we don't have credentials
			 * BUT they are not needed.
			 */
			switch (next_step)
			{
			case fos_myid_ip_txt:
				if (c->spd.this.id->get_type(c->spd.this.id) == ID_MYID
				&& myid_state != MYID_SPECIFIED)
				{
					cr->b.failure_ok = TRUE;
					cr->b.want = b->want = "TXT record for IP address as %myid";
					ugh = start_adns_query(myids[MYID_IP], myids[MYID_IP],
										   T_TXT, continue_oppo, &cr->ac);
					break;
				}
				cr->b.step = fos_myid_hostname_txt;
				/* fall through */

			case fos_myid_hostname_txt:
				if (c->spd.this.id->get_type(c->spd.this.id) == ID_MYID
				&& myid_state != MYID_SPECIFIED)
				{
#ifdef USE_KEYRR
					cr->b.failure_ok = TRUE;
#else
					cr->b.failure_ok = FALSE;
#endif
					cr->b.want = b->want = "TXT record for hostname as %myid";
					ugh = start_adns_query(myids[MYID_HOSTNAME],
										   myids[MYID_HOSTNAME],
										   T_TXT, continue_oppo, &cr->ac);
					break;
				}

#ifdef USE_KEYRR
				cr->b.step = fos_myid_ip_key;
				/* fall through */

			case fos_myid_ip_key:
				if (c->spd.this.id.kind == ID_MYID
				&& myid_state != MYID_SPECIFIED)
				{
					cr->b.failure_ok = TRUE;
					cr->b.want = b->want = "KEY record for IP address as %myid (no good TXT)";
					ugh = start_adns_query(myids[MYID_IP], NULL, /* security gateway meaningless */
										   T_KEY, continue_oppo, &cr->ac);
					break;
				}
				cr->b.step = fos_myid_hostname_key;
				/* fall through */

			case fos_myid_hostname_key:
				if (c->spd.this.id.kind == ID_MYID
				&& myid_state != MYID_SPECIFIED)
				{
					cr->b.failure_ok = FALSE;           /* last attempt! */
					cr->b.want = b->want = "KEY record for hostname as %myid (no good TXT)";
					ugh = start_adns_query(myids[MYID_HOSTNAME], NULL, /* security gateway meaningless */
										   T_KEY, continue_oppo, &cr->ac);
					break;
				}
#endif
				cr->b.step = fos_our_client;
				/* fall through */

			case fos_our_client:        /* TXT for our client */
				if (!sameaddr(&c->spd.this.host_addr, &b->our_client))
				{
					/* Check that at least one TXT(reverse(b->our_client)) is workable.
					 * Note: {unshare|free}_id_content not needed for id: ephemeral.
					 */
					cr->b.want = b->want = "our client's TXT record";
					id = identification_create_from_sockaddr((sockaddr_t*)&b->our_client);
					ugh = start_adns_query(id, c->spd.this.id, /* we are the security gateway */
										   T_TXT, continue_oppo, &cr->ac);
					id->destroy(id);
					break;
				}
				cr->b.step = fos_our_txt;
				/* fall through */

			case fos_our_txt:   /* TXT for us */
				cr->b.failure_ok = b->failure_ok = TRUE;
				cr->b.want = b->want = "our TXT record";
				ugh = start_adns_query(sr->this.id, sr->this.id, /* we are the security gateway */
									   T_TXT, continue_oppo, &cr->ac);
				break;

#ifdef USE_KEYRR
			case fos_our_key:   /* KEY for us */
				cr->b.want = b->want = "our KEY record";
				cr->b.failure_ok = b->failure_ok = FALSE;
				ugh = start_adns_query(sr->this.id, NULL,  /* security gateway meaningless */
									   T_KEY, continue_oppo, &cr->ac);
				break;
#endif /* USE_KEYRR */

			case fos_his_client:        /* TXT for his client */
				/* note: {unshare|free}_id_content not needed for id: ephemeral */
				cr->b.want = b->want = "target's TXT record";
				cr->b.failure_ok = b->failure_ok = FALSE;
				id = identification_create_from_sockaddr((sockaddr_t*)&b->peer_client);
				ugh = start_adns_query(id, NULL, /* security gateway unconstrained */
									   T_TXT, continue_oppo, &cr->ac);
				id->destroy(id);
				break;

			default:
				bad_case(next_step);
			}

			if (ugh == NULL)
				b->whackfd = NULL_FD;   /* complete hand-off */
			else
				cannot_oppo(c, b, ugh);
		}
	}
#endif /* ADNS */
	close_any(b->whackfd);
}

void terminate_connection(const char *nm)
{
	/* Loop because more than one may match (master and instances)
	 * But at least one is required (enforced by con_by_name).
	 */
	connection_t *c = con_by_name(nm, TRUE);

	if (c == NULL || !c->ikev1)
		return;

	do
	{
		connection_t *n = c->ac_next;  /* grab this before c might disappear */

		if (streq(c->name, nm)
		&& c->kind >= CK_PERMANENT
		&& !NEVER_NEGOTIATE(c->policy))
		{
			set_cur_connection(c);
			plog("terminating SAs using this connection");
			c->policy &= ~POLICY_UP;
			flush_pending_by_connection(c);
			delete_states_by_connection(c, FALSE);
			if (c->kind == CK_INSTANCE)
				delete_connection(c, FALSE);
			reset_cur_connection();
		}
		c = n;
	} while (c);
}

/* an ISAKMP SA has been established.
 * Note the serial number, and release any connections with
 * the same peer ID but different peer IP address.
 */
bool uniqueIDs = FALSE; /* --uniqueids? */

void ISAKMP_SA_established(connection_t *c, so_serial_t serial)
{
	c->newest_isakmp_sa = serial;

	/* the connection is now oriented so that we are able to determine
	 * whether we are a mode config server with a virtual IP to send.
	 */
	if (!c->spd.that.host_srcip->is_anyaddr(c->spd.that.host_srcip) &&
	    !c->spd.that.has_natip)
	{
		c->spd.that.modecfg = TRUE;
	}

	if (uniqueIDs)
	{
		/* for all connections: if the same Phase 1 IDs are used
		 * for a different IP address, unorient that connection.
		 */
		connection_t *d;

		for (d = connections; d != NULL; )
		{
			connection_t *next = d->ac_next;       /* might move underneath us */

			if (d->kind >= CK_PERMANENT &&
				c->spd.this.id->equals(c->spd.this.id, d->spd.this.id) &&
				c->spd.that.id->equals(c->spd.that.id, d->spd.that.id) &&
				!sameaddr(&c->spd.that.host_addr, &d->spd.that.host_addr))
			{
				release_connection(d, FALSE);
			}
			d = next;
		}
	}
}

/* Find the connection to connection c's peer's client with the
 * largest value of .routing.  All other things being equal,
 * preference is given to c.  If none is routed, return NULL.
 *
 * If erop is non-null, set *erop to a connection sharing both
 * our client subnet and peer's client subnet with the largest value
 * of .routing.  If none is erouted, set *erop to NULL.
 *
 * The return value is used to find other connections sharing a route.
 * *erop is used to find other connections sharing an eroute.
 */
connection_t *route_owner(connection_t *c, struct spd_route **srp,
						  connection_t **erop, struct spd_route **esrp)
{
	connection_t *d
		, *best_ro = c
		, *best_ero = c;
	struct spd_route *srd, *src;
	struct spd_route *best_sr, *best_esr;
	enum routing_t best_routing, best_erouting;

	passert(oriented(*c));
	best_sr  = NULL;
	best_esr = NULL;
	best_routing = c->spd.routing;
	best_erouting = best_routing;

	for (d = connections; d != NULL; d = d->ac_next)
	{
		for (srd = &d->spd; srd; srd = srd->next)
		{
			if (srd->routing == RT_UNROUTED)
				continue;

			for (src = &c->spd; src; src=src->next)
			{
				if (!samesubnet(&src->that.client, &srd->that.client))
				{
					continue;
				}
				if (src->that.protocol != srd->that.protocol)
				{
					continue;
				}
				if (src->that.port != srd->that.port)
				{
					continue;
				}
				if (src->mark_out.value != srd->mark_out.value)
				{
					continue;
				}
				passert(oriented(*d));
				if (srd->routing > best_routing)
				{
					best_ro = d;
					best_sr = srd;
					best_routing = srd->routing;
				}

				if (!samesubnet(&src->this.client, &srd->this.client))
				{
					continue;
				}
				if (src->this.protocol != srd->this.protocol)
				{
					continue;
				}
				if (src->this.port != srd->this.port)
				{
					continue;
				}
				if (src->mark_in.value != srd->mark_in.value)
				{
					continue;
				}
				if (srd->routing > best_erouting)
				{
					best_ero = d;
					best_esr = srd;
					best_erouting = srd->routing;
				}
			}
		}
	}

	DBG(DBG_CONTROL,
		{
			char cib[CONN_INST_BUF];
			err_t m = builddiag("route owner of \"%s\"%s %s:"
				, c->name
				, (fmt_conn_instance(c, cib), cib)
				, enum_name(&routing_story, c->spd.routing));

			if (!routed(best_ro->spd.routing))
				m = builddiag("%s NULL", m);
			else if (best_ro == c)
				m = builddiag("%s self", m);
			else
				m = builddiag("%s \"%s\"%s %s", m
					, best_ro->name
					, (fmt_conn_instance(best_ro, cib), cib)
					, enum_name(&routing_story, best_ro->spd.routing));

			if (erop)
			{
				m = builddiag("%s; eroute owner:", m);
				if (!erouted(best_ero->spd.routing))
					m = builddiag("%s NULL", m);
				else if (best_ero == c)
					m = builddiag("%s self", m);
				else
					m = builddiag("%s \"%s\"%s %s", m
						, best_ero->name
						, (fmt_conn_instance(best_ero, cib), cib)
						, enum_name(&routing_story, best_ero->spd.routing));
			}

			DBG_log("%s", m);
		});

	if (erop)
	{
		*erop = erouted(best_erouting)? best_ero : NULL;
	}
	if (srp)
	{
		*srp = best_sr;
		if (esrp)
		{
			*esrp = best_esr;
		}
	}

	return routed(best_routing)? best_ro : NULL;
}

/* Find a connection that owns the shunt eroute between subnets.
 * There ought to be only one.
 * This might get to be a bottleneck -- try hashing if it does.
 */
connection_t *shunt_owner(const ip_subnet *ours, const ip_subnet *his)
{
	connection_t *c;
	struct spd_route *sr;

	for (c = connections; c != NULL; c = c->ac_next)
	{
		for (sr = &c->spd; sr; sr = sr->next)
		{
			if (shunt_erouted(sr->routing)
			&& samesubnet(ours, &sr->this.client)
			&& samesubnet(his, &sr->that.client))
				return c;
		}
	}
	return NULL;
}

/* Find some connection with this pair of hosts.
 * We don't know enough to chose amongst those available.
 * ??? no longer usefully different from find_host_pair_connections
 */
connection_t *find_host_connection(const ip_address *me, u_int16_t my_port,
								   const ip_address *him, u_int16_t his_port,
								   lset_t policy)
{
	connection_t *c = find_host_pair_connections(me, my_port, him, his_port);

	if (policy != LEMPTY)
	{
		lset_t auth_requested  = policy & POLICY_ID_AUTH_MASK;

		/* if we have requirements for the policy,
		 * choose the first matching connection.
		 */
		while (c)
		{
			if (c->policy & auth_requested)
			{
				break;
			}
			c = c->hp_next;
		}
	}
	return c;
}

/* given an up-until-now satisfactory connection, find the best connection
 * now that we just got the Phase 1 Id Payload from the peer.
 *
 * Comments in the code describe the (tricky!) matching criteria.
 * Although this routine could handle the initiator case,
 * it isn't currently called in this case.
 * If it were, it could "upgrade" an Opportunistic Connection
 * to a Road Warrior Connection if a suitable Peer ID were found.
 *
 * In RFC 2409 "The Internet Key Exchange (IKE)",
 * in 5.1 "IKE Phase 1 Authenticated With Signatures", describing Main
 * Mode:
 *
 *         Initiator                          Responder
 *        -----------                        -----------
 *         HDR, SA                     -->
 *                                     <--    HDR, SA
 *         HDR, KE, Ni                 -->
 *                                     <--    HDR, KE, Nr
 *         HDR*, IDii, [ CERT, ] SIG_I -->
 *                                     <--    HDR*, IDir, [ CERT, ] SIG_R
 *
 * In 5.4 "Phase 1 Authenticated With a Pre-Shared Key":
 *
 *               HDR, SA             -->
 *                                   <--    HDR, SA
 *               HDR, KE, Ni         -->
 *                                   <--    HDR, KE, Nr
 *               HDR*, IDii, HASH_I  -->
 *                                   <--    HDR*, IDir, HASH_R
 *
 * refine_host_connection could be called in two case:
 *
 * - the Responder receives the IDii payload:
 *   + [PSK] after using PSK to decode this message
 *   + before sending its IDir payload
 *   + before using its ID in HASH_R computation
 *   + [DSig] before using its private key to sign SIG_R
 *   + before using the Initiator's ID in HASH_I calculation
 *   + [DSig] before using the Initiator's public key to check SIG_I
 *
 * - the Initiator receives the IDir payload:
 *   + [PSK] after using PSK to encode previous message and decode this message
 *   + after sending its IDii payload
 *   + after using its ID in HASH_I computation
 *   + [DSig] after using its private key to sign SIG_I
 *   + before using the Responder's ID to compute HASH_R
 *   + [DSig] before using Responder's public key to check SIG_R
 *
 * refine_host_connection can choose a different connection, as long as
 * nothing already used is changed.
 *
 * In the Initiator case, the particular connection might have been
 * specified by whatever provoked Pluto to initiate.  For example:
 *      whack --initiate connection-name
 * The advantages of switching connections when we're the Initiator seem
 * less important than the disadvantages, so after FreeS/WAN 1.9, we
 * don't do this.
 */
#define PRIO_NO_MATCH_FOUND     2048

connection_t *refine_host_connection(const struct state *st,
									 identification_t *peer_id,
									 identification_t *peer_ca)
{
	connection_t *c = st->st_connection;
	connection_t *d;
	connection_t *best_found = NULL;
	u_int16_t auth = st->st_oakley.auth;
	lset_t auth_policy = POLICY_PSK;
	const chunk_t *psk = NULL;
	bool wcpip; /* wildcard Peer IP? */
	int best_prio = PRIO_NO_MATCH_FOUND;
	int our_pathlen, peer_pathlen;

	if (c->spd.that.id->equals(c->spd.that.id, peer_id) &&
		trusted_ca(peer_ca, c->spd.that.ca, &peer_pathlen) &&
		peer_pathlen == 0 &&
		match_requested_ca(c->requested_ca, c->spd.this.ca, &our_pathlen) &&
		our_pathlen == 0)
	{
		DBG(DBG_CONTROL,
			DBG_log("current connection is a full match"
					" -- no need to look further");
		)
		return c;
	}

	switch (auth)
	{
	case OAKLEY_PRESHARED_KEY:
		auth_policy = POLICY_PSK;
		psk = get_preshared_secret(c);
		/* It should be virtually impossible to fail to find PSK:
		 * we just used it to decode the current message!
		 */
		if (psk == NULL)
		{
			return NULL;        /* cannot determine PSK! */
		}
		break;
	case XAUTHInitPreShared:
	case XAUTHRespPreShared:
		auth_policy = POLICY_XAUTH_PSK;
		psk = get_preshared_secret(c);
		if (psk == NULL)
		{
			return NULL;        /* cannot determine PSK! */
		}
		break;
	case OAKLEY_RSA_SIG:
	case OAKLEY_ECDSA_256:
	case OAKLEY_ECDSA_384:
	case OAKLEY_ECDSA_521:
		auth_policy = POLICY_PUBKEY;
		break;
	case XAUTHInitRSA:
	case XAUTHRespRSA:
		auth_policy = POLICY_XAUTH_RSASIG;
		break;
	default:
		bad_case(auth);
	}

	/* The current connection won't do: search for one that will.
	 * First search for one with the same pair of hosts.
	 * If that fails, search for a suitable Road Warrior or Opportunistic
	 * connection (i.e. wildcard peer IP).
	 * We need to match:
	 * - peer_id (slightly complicated by instantiation)
	 * - if PSK auth, the key must not change (we used it to decode message)
	 * - policy-as-used must be acceptable to new connection
	 */
	d = c->host_pair->connections;
	for (wcpip = FALSE; ; wcpip = TRUE)
	{
		for (; d != NULL; d = d->hp_next)
		{
			const char *match_name[] = {"no", "ok"};

			id_match_t match_level = peer_id->matches(peer_id, d->spd.that.id);

			bool matching_id = match_level > ID_MATCH_NONE;

			bool matching_auth = (d->policy & auth_policy) != LEMPTY;

			bool matching_trust = trusted_ca(peer_ca
										, d->spd.that.ca, &peer_pathlen);
			bool matching_request = match_requested_ca(c->requested_ca
										, d->spd.this.ca, &our_pathlen);
			bool match = matching_id && matching_auth && matching_trust;

			int prio = (ID_MATCH_PERFECT) * !matching_request +
						ID_MATCH_PERFECT - match_level;

			prio = (X509_MAX_PATH_LEN + 1) * prio + peer_pathlen;
			prio = (X509_MAX_PATH_LEN + 1) * prio + our_pathlen;

			DBG(DBG_CONTROLMORE,
				DBG_log("%s: %s match (id: %s, auth: %s, trust: %s, request: %s, prio: %4d)"
					, d->name
					, match ? "full":" no"
					, match_name[matching_id]
					, match_name[matching_auth]
					, match_name[matching_trust]
					, match_name[matching_request]
					, match ? prio:PRIO_NO_MATCH_FOUND)
			)

			/* do we have a match? */
			if (!match)
			{
				continue;
			}

			/* ignore group connections */
			if (d->policy & POLICY_GROUP)
			{
				continue;
			}

			if (c->spd.that.host_port != d->spd.that.host_port
			&& d->kind == CK_INSTANCE)
			{
				continue;
			}

			switch (auth)
			{
			case OAKLEY_PRESHARED_KEY:
			case XAUTHInitPreShared:
			case XAUTHRespPreShared:
				/* secret must match the one we already used */
				{
					const chunk_t *dpsk = get_preshared_secret(d);

					if (dpsk == NULL)
					{
						continue;       /* no secret */
					}
					if (psk != dpsk)
					{
						if (psk->len != dpsk->len
						|| memcmp(psk->ptr, dpsk->ptr, psk->len) != 0)
						{
							continue;   /* different secret */
						}
					}
				}
				break;

			case OAKLEY_RSA_SIG:
			case OAKLEY_ECDSA_256:
			case OAKLEY_ECDSA_384:
			case OAKLEY_ECDSA_521:
			case XAUTHInitRSA:
			case XAUTHRespRSA:
				/*
				 * We must at least be able to find our private key
				.*/
				if (d->spd.this.sc == NULL              /* no smartcard */
				&& get_private_key(d) == NULL)      /* no private key */
				{
					continue;
				}
				break;

			default:
				bad_case(auth);
			}

			/* d has passed all the tests.
			 * We'll go with it if the Peer ID was an exact match.
			 */
			if (prio == 0)
			{
				return d;
			}

			/* We'll remember it as best_found in case an exact
			 * match doesn't come along.
			 */
			if (prio < best_prio)
			{
				best_found = d;
				best_prio = prio;
			}
		}
		if (wcpip)
			return best_found;  /* been around twice already */

		/* Starting second time around.
		 * We're willing to settle for a connection that needs Peer IP
		 * instantiated: Road Warrior or Opportunistic.
		 * Look on list of connections for host pair with wildcard Peer IP
		 */
		d = find_host_pair_connections(&c->spd.this.host_addr, c->spd.this.host_port
			, (ip_address *)NULL, c->spd.that.host_port);
	}
}

/**
 * With virtual addressing, we must not allow someone to use an already
 * used (by another id) addr/net.
 */
static bool is_virtual_net_used(const ip_subnet *peer_net,
								identification_t *peer_id)
{
	connection_t *d;

	for (d = connections; d != NULL; d = d->ac_next)
	{
		switch (d->kind)
		{
		case CK_PERMANENT:
		case CK_INSTANCE:
			if ((subnetinsubnet(peer_net,&d->spd.that.client) ||
				 subnetinsubnet(&d->spd.that.client,peer_net))
			&& !d->spd.that.id->equals(d->spd.that.id, peer_id))
			{
				char client[SUBNETTOT_BUF];

				subnettot(peer_net, 0, client, sizeof(client));
				plog("Virtual IP %s is already used by '%Y'",
						 client, d->spd.that.id);
				plog("Your ID is '%Y'", peer_id);

				return TRUE; /* already used by another one */
			}
			break;
		case CK_GOING_AWAY:
		default:
		break;
		}
	}
	return FALSE; /* you can safely use it */
}

/* find_client_connection: given a connection suitable for ISAKMP
 * (i.e. the hosts match), find a one suitable for IPSEC
 * (i.e. with matching clients).
 *
 * If we don't find an exact match (not even our current connection),
 * we try for one that still needs instantiation.  Try Road Warrior
 * abstract connections and the Opportunistic abstract connections.
 * This requires inverse instantiation: abstraction.
 *
 * After failing to find an exact match, we abstract the peer
 * to be NO_IP (the wildcard value).  This enables matches with
 * Road Warrior and Opportunistic abstract connections.
 *
 * After failing that search, we also abstract the Phase 1 peer ID
 * if possible.  If the peer's ID was the peer's IP address, we make
 * it NO_ID; instantiation will make it the peer's IP address again.
 *
 * If searching for a Road Warrior abstract connection fails,
 * and conditions are suitable, we search for the best Opportunistic
 * abstract connection.
 *
 * Note: in the end, both Phase 1 IDs must be preserved, after any
 * instantiation.  They are the IDs that have been authenticated.
 */

#define PATH_WEIGHT     1
#define WILD_WEIGHT     (X509_MAX_PATH_LEN+1)
#define PRIO_WEIGHT     (ID_MATCH_PERFECT+1) * WILD_WEIGHT

/* fc_try: a helper function for find_client_connection */
static connection_t *fc_try(const connection_t *c, struct host_pair *hp,
							identification_t *peer_id,
							const ip_subnet *our_net,
							const ip_subnet *peer_net,
							const u_int8_t our_protocol,
							const u_int16_t our_port,
							const u_int8_t peer_protocol,
							const u_int16_t peer_port,
							identification_t *peer_ca,
							ietf_attributes_t *peer_attributes)
{
	connection_t *d;
	connection_t *best = NULL;
	policy_prio_t best_prio = BOTTOM_PRIO;
	id_match_t match_level;
	int pathlen;


	const bool peer_net_is_host = subnetisaddr(peer_net, &c->spd.that.host_addr);

	for (d = hp->connections; d != NULL; d = d->hp_next)
	{
		struct spd_route *sr;

		if (d->policy & POLICY_GROUP)
		{
			continue;
		}

		match_level = c->spd.that.id->matches(c->spd.that.id, d->spd.that.id);

		if (!(c->spd.this.id->equals(c->spd.this.id, d->spd.this.id) &&
			(match_level > ID_MATCH_NONE) &&
			trusted_ca(peer_ca, d->spd.that.ca, &pathlen) &&
			match_group_membership(peer_attributes, d->name, d->spd.that.groups)))
		{
			continue;
		}

		/* compare protocol and ports */
		if (d->spd.this.protocol != our_protocol
		||  d->spd.this.port != our_port
		||  d->spd.that.protocol != peer_protocol
		|| (d->spd.that.port != peer_port && !d->spd.that.has_port_wildcard))
		{
			continue;
		}

		/* non-Opportunistic case:
		 * our_client must match.
		 *
		 * So must peer_client, but the testing is complicated
		 * by the fact that the peer might be a wildcard
		 * and if so, the default value of that.client
		 * won't match the default peer_net.  The appropriate test:
		 *
		 * If d has a peer client, it must match peer_net.
		 * If d has no peer client, peer_net must just have peer itself.
		 */

		for (sr = &d->spd; best != d && sr != NULL; sr = sr->next)
		{
			policy_prio_t prio;
#ifdef DEBUG
			if (DBGP(DBG_CONTROLMORE))
			{
				char s1[SUBNETTOT_BUF],d1[SUBNETTOT_BUF];
				char s3[SUBNETTOT_BUF],d3[SUBNETTOT_BUF];

				subnettot(our_net,  0, s1, sizeof(s1));
				subnettot(peer_net, 0, d1, sizeof(d1));
				subnettot(&sr->this.client,  0, s3, sizeof(s3));
				subnettot(&sr->that.client,  0, d3, sizeof(d3));
				DBG_log("  fc_try trying "
						"%s:%s:%d/%d -> %s:%d/%d vs %s:%s:%d/%d -> %s:%d/%d"
						, c->name, s1, c->spd.this.protocol, c->spd.this.port
								 , d1, c->spd.that.protocol, c->spd.that.port
						, d->name, s3, sr->this.protocol, sr->this.port
								 , d3, sr->that.protocol, sr->that.port);
			}
#endif /* DEBUG */

			if (!samesubnet(&sr->this.client, our_net))
			{
				continue;
			}
			if (sr->that.has_client)
			{
				if (sr->that.has_client_wildcard)
				{
					if (!subnetinsubnet(peer_net, &sr->that.client))
					{
						continue;
					}
				}
				else
				{
					if (!samesubnet(&sr->that.client, peer_net) && !is_virtual_connection(d))
					{
						continue;
					}
					if (is_virtual_connection(d)
					&& (!is_virtual_net_allowed(d, peer_net, &c->spd.that.host_addr)
						|| is_virtual_net_used(peer_net, peer_id?peer_id:c->spd.that.id)))
					{
						continue;
					}
				}
			}
			else
			{
				host_t *vip = c->spd.that.host_srcip;

				if (!peer_net_is_host && !(sr->that.modecfg && c->spd.that.modecfg &&
						subnetisaddr(peer_net, (ip_address*)vip->get_sockaddr(vip))))
				{
					continue;
				}
			}

			/* We've run the gauntlet -- success:
			 * We've got an exact match of subnets.
			 * The connection is feasible, but we continue looking for the best.
			 * The highest priority wins, implementing eroute-like rule.
			 * - a routed connection is preferrred
			 * - given that, the smallest number of ID wildcards are preferred
			 * - given that, the shortest CA pathlength is preferred
			 */
			prio = PRIO_WEIGHT * routed(sr->routing)
				 + WILD_WEIGHT * match_level
				 + PATH_WEIGHT * (X509_MAX_PATH_LEN - pathlen)
				 + 1;
			if (prio > best_prio)
			{
				best = d;
				best_prio = prio;
			}
		}
	}

	if (best && NEVER_NEGOTIATE(best->policy))
	{
		best = NULL;
	}
	DBG(DBG_CONTROLMORE,
		DBG_log("  fc_try concluding with %s [%ld]"
				, (best ? best->name : "none"), best_prio)
	)
	return best;
}

static connection_t *fc_try_oppo(const connection_t *c,
								 struct host_pair *hp,
								 const ip_subnet *our_net,
								 const ip_subnet *peer_net,
								 const u_int8_t our_protocol,
								 const u_int16_t our_port,
								 const u_int8_t peer_protocol,
								 const u_int16_t peer_port,
								 identification_t *peer_ca,
								 ietf_attributes_t *peer_attributes)
{
	connection_t *d;
	connection_t *best = NULL;
	policy_prio_t best_prio = BOTTOM_PRIO;
	id_match_t match_level;
	int pathlen;

	for (d = hp->connections; d != NULL; d = d->hp_next)
	{
		struct spd_route *sr;
		policy_prio_t prio;

		if (d->policy & POLICY_GROUP)
		{
			continue;
		}
		match_level = c->spd.that.id->matches(c->spd.that.id, c->spd.that.id);

		if (!(c->spd.this.id->equals(c->spd.this.id, d->spd.this.id) &&
			(match_level > ID_MATCH_NONE) &&
			trusted_ca(peer_ca, d->spd.that.ca, &pathlen) &&
			match_group_membership(peer_attributes, d->name, d->spd.that.groups)))
		{
			continue;
		}

		/* compare protocol and ports */
		if (d->spd.this.protocol != our_protocol
		||  d->spd.this.port != our_port
		||  d->spd.that.protocol != peer_protocol
		|| (d->spd.that.port != peer_port && !d->spd.that.has_port_wildcard))
		{
			continue;
		}

		/* Opportunistic case:
		 * our_net must be inside d->spd.this.client
		 * and peer_net must be inside d->spd.that.client
		 * Note: this host_pair chain also has shunt
		 * eroute conns (clear, drop), but they won't
		 * be marked as opportunistic.
		 */
		for (sr = &d->spd; sr != NULL; sr = sr->next)
		{
#ifdef DEBUG
			if (DBGP(DBG_CONTROLMORE))
			{
				char s1[SUBNETTOT_BUF],d1[SUBNETTOT_BUF];
				char s3[SUBNETTOT_BUF],d3[SUBNETTOT_BUF];

				subnettot(our_net,  0, s1, sizeof(s1));
				subnettot(peer_net, 0, d1, sizeof(d1));
				subnettot(&sr->this.client,  0, s3, sizeof(s3));
				subnettot(&sr->that.client,  0, d3, sizeof(d3));
				DBG_log("  fc_try_oppo trying %s:%s -> %s vs %s:%s -> %s"
						, c->name, s1, d1, d->name, s3, d3);
			}
#endif /* DEBUG */

			if (!subnetinsubnet(our_net, &sr->this.client)
			|| !subnetinsubnet(peer_net, &sr->that.client))
			{
				continue;
			}

			/* The connection is feasible, but we continue looking for the best.
			 * The highest priority wins, implementing eroute-like rule.
			 * - our smallest client subnet is preferred (longest mask)
			 * - given that, his smallest client subnet is preferred
			 * - given that, a routed connection is preferrred
			 * - given that, the smallest number of ID wildcards are preferred
			 * - given that, the shortest CA pathlength is preferred
			 */
			prio = PRIO_WEIGHT * (d->prio + routed(sr->routing))
				 + WILD_WEIGHT * match_level
				 + PATH_WEIGHT * (X509_MAX_PATH_LEN - pathlen);
			if (prio > best_prio)
			{
				best = d;
				best_prio = prio;
			}
		}
	}

	/* if the best wasn't opportunistic, we fail: it must be a shunt */
	if (best && (NEVER_NEGOTIATE(best->policy) ||
	   (best->policy & POLICY_OPPO) == LEMPTY))
	{
		best = NULL;
	}

	DBG(DBG_CONTROLMORE,
		DBG_log("  fc_try_oppo concluding with %s [%ld]"
				, (best ? best->name : "none"), best_prio)
	)
	return best;

}

/*
 * get the peer's CA and group attributes
 */
void get_peer_ca_and_groups(connection_t *c,
							identification_t **peer_ca,
							ietf_attributes_t **peer_attributes)
{
	struct state *p1st;

	*peer_ca = NULL;
	*peer_attributes = NULL;

	p1st = find_phase1_state(c, ISAKMP_SA_ESTABLISHED_STATES);
	if (p1st && p1st->st_peer_pubkey && p1st->st_peer_pubkey->issuer)
	{
		certificate_t *cert;

		cert = ac_get_cert(p1st->st_peer_pubkey->issuer,
						   p1st->st_peer_pubkey->serial);
		if (cert && ac_verify_cert(cert, strict_crl_policy))
		{
			ac_t *ac = (ac_t*)cert;

			*peer_attributes = ac->get_groups(ac);
		}
		else
		{
			DBG(DBG_CONTROL,
				DBG_log("no valid attribute cert found")
			)
		}
		*peer_ca = p1st->st_peer_pubkey->issuer;
	}
}

connection_t *find_client_connection(connection_t *c,
									 const ip_subnet *our_net,
									 const ip_subnet *peer_net,
									 const u_int8_t our_protocol,
									 const u_int16_t our_port,
									 const u_int8_t peer_protocol,
									 const u_int16_t peer_port)
{
	connection_t *d;
	struct spd_route *sr;
	ietf_attributes_t *peer_attributes = NULL;
	identification_t *peer_ca;

	get_peer_ca_and_groups(c, &peer_ca, &peer_attributes);

#ifdef DEBUG
	if (DBGP(DBG_CONTROLMORE))
	{
		char s1[SUBNETTOT_BUF],d1[SUBNETTOT_BUF];

		subnettot(our_net,  0, s1, sizeof(s1));
		subnettot(peer_net, 0, d1, sizeof(d1));

		DBG_log("find_client_connection starting with %s"
			, (c ? c->name : "(none)"));
		DBG_log("  looking for %s:%d/%d -> %s:%d/%d"
			, s1, our_protocol, our_port
			, d1, peer_protocol, peer_port);
	}
#endif /* DEBUG */

	/* give priority to current connection
	 * but even greater priority to a routed concrete connection
	 */
	{
		connection_t *unrouted = NULL;
		int srnum = -1;

		for (sr = &c->spd; unrouted == NULL && sr != NULL; sr = sr->next)
		{
			srnum++;

#ifdef DEBUG
			if (DBGP(DBG_CONTROLMORE))
			{
				char s2[SUBNETTOT_BUF],d2[SUBNETTOT_BUF];

				subnettot(&sr->this.client, 0, s2, sizeof(s2));
				subnettot(&sr->that.client, 0, d2, sizeof(d2));
				DBG_log("  concrete checking against sr#%d %s -> %s"
						, srnum, s2, d2);
			}
#endif /* DEBUG */

			if (samesubnet(&sr->this.client, our_net)
			&& samesubnet(&sr->that.client, peer_net)
			&& sr->this.protocol == our_protocol
			&& sr->this.port == our_port
			&& sr->that.protocol == peer_protocol
			&& sr->that.port == peer_port
			&& match_group_membership(peer_attributes, c->name, sr->that.groups))
			{
				passert(oriented(*c));
				if (routed(sr->routing))
				{
					DESTROY_IF(peer_attributes);
					return c;
				}
				unrouted = c;
			}
		}

		/* exact match? */
		d = fc_try(c, c->host_pair, NULL, our_net, peer_net
			, our_protocol, our_port, peer_protocol, peer_port
			, peer_ca, peer_attributes);

		DBG(DBG_CONTROLMORE,
			DBG_log("  fc_try %s gives %s"
					, c->name
					, (d ? d->name : "none"))
		)

		if (d == NULL)
		{
			d = unrouted;
		}
	}

	if (d == NULL)
	{
		/* look for an abstract connection to match */
		struct spd_route *sr;
		struct host_pair *hp = NULL;

		for (sr = &c->spd; hp==NULL && sr != NULL; sr = sr->next)
		{
			hp = find_host_pair(&sr->this.host_addr
								, sr->this.host_port
								, NULL
								, sr->that.host_port);
#ifdef DEBUG
			if (DBGP(DBG_CONTROLMORE))
			{
				char s2[SUBNETTOT_BUF],d2[SUBNETTOT_BUF];

				subnettot(&sr->this.client, 0, s2, sizeof(s2));
				subnettot(&sr->that.client, 0, d2, sizeof(d2));

				DBG_log("  checking hostpair %s -> %s is %s"
						, s2, d2
						, (hp ? "found" : "not found"));
			}
#endif /* DEBUG */
		}

		if (hp)
		{
			/* RW match with actual peer_id or abstract peer_id? */
			d = fc_try(c, hp, NULL, our_net, peer_net
				, our_protocol, our_port, peer_protocol, peer_port
				, peer_ca, peer_attributes);

			if (d == NULL
			&& subnetishost(our_net)
			&& subnetishost(peer_net))
			{
				/* Opportunistic match?
				 * Always use abstract peer_id.
				 * Note that later instantiation will result in the same peer_id.
				 */
				d = fc_try_oppo(c, hp, our_net, peer_net
					, our_protocol, our_port, peer_protocol, peer_port
					, peer_ca, peer_attributes);
			}
		}
	}

	DBG(DBG_CONTROLMORE,
		DBG_log("  concluding with d = %s"
				, (d ? d->name : "none"))
	)
	DESTROY_IF(peer_attributes);
	return d;
}

int connection_compare(const connection_t *ca, const connection_t *cb)
{
	int ret;

	/* DBG_log("comparing %s to %s", ca->name, cb->name);  */

	ret = strcasecmp(ca->name, cb->name);
	if (ret)
	{
		return ret;
	}

	ret = ca->kind - cb->kind;  /* note: enum connection_kind behaves like int */
	if (ret)
	{
		return ret;
	}

	/* same name, and same type */
	switch (ca->kind)
	{
	case CK_INSTANCE:
		return ca->instance_serial < cb->instance_serial ? -1
			: ca->instance_serial > cb->instance_serial ? 1
			: 0;

	default:
		return ca->prio < cb->prio ? -1
			: ca->prio > cb->prio ? 1
			: 0;
	}
}

static int connection_compare_qsort(const void *a, const void *b)
{
	return connection_compare(*(const connection_t *const *)a
							, *(const connection_t *const *)b);
}

void show_connections_status(bool all, const char *name)
{
	connection_t *c;
	int count, i;
	connection_t **array;

	/* make an array of connections, and sort it */
	count = 0;
	for (c = connections; c != NULL; c = c->ac_next)
	{
		if (c->ikev1 && (name == NULL || streq(c->name, name)))
			count++;
	}
	array = malloc(sizeof(connection_t *)*count);

	count=0;
	for (c = connections; c != NULL; c = c->ac_next)
	{
		if (c->ikev1 && (name == NULL || streq(c->name, name)))
			array[count++]=c;
	}

	/* sort it! */
	qsort(array, count, sizeof(connection_t *), connection_compare_qsort);

	for (i = 0; i < count; i++)
	{
		const char *ifn;
		char instance[1 + 10 + 1];
		char prio[POLICY_PRIO_BUF];

		c = array[i];

		ifn = oriented(*c)? c->interface->rname : "";

		instance[0] = '\0';
		if (c->kind == CK_INSTANCE && c->instance_serial != 0)
			snprintf(instance, sizeof(instance), "[%lu]", c->instance_serial);

		/* show topology */
		{
			char topo[BUF_LEN];
			struct spd_route *sr = &c->spd;
			int num=0;

			while (sr)
			{
				(void) format_connection(topo, sizeof(topo), c, sr);
				whack_log(RC_COMMENT, "\"%s\"%s: %s; %s; eroute owner: #%lu"
						  , c->name, instance, topo
						  , enum_name(&routing_story, sr->routing)
						  , sr->eroute_owner);
				sr = sr->next;
				num++;
			}
		}

		if (all)
		{
			/* show CAs if defined */
			if (c->spd.this.ca && c->spd.that.ca)
			{
				whack_log(RC_COMMENT, "\"%s\"%s:   CAs: \"%Y\"...\"%Y\"",
						  c->name, instance, c->spd.this.ca, c->spd.that.ca);
			}
			else if (c->spd.this.ca)
			{
				whack_log(RC_COMMENT, "\"%s\"%s:   CAs: \"%Y\"...%%any",
						  c->name, instance, c->spd.this.ca);

			}
			else if (c->spd.that.ca)
			{
				whack_log(RC_COMMENT, "\"%s\"%s:   CAs: %%any...\"%Y\"",
						  c->name, instance, c->spd.that.ca);
			}

			/* show group attributes if defined */
			if (c->spd.that.groups)
			{
				whack_log(RC_COMMENT, "\"%s\"%s:   groups: %s"
					, c->name
					, instance
					, c->spd.that.groups->get_string(c->spd.that.groups));
			}

			whack_log(RC_COMMENT
				, "\"%s\"%s:   ike_life: %lus; ipsec_life: %lus;"
				" rekey_margin: %lus; rekey_fuzz: %lu%%; keyingtries: %lu"
				, c->name
				, instance
				, (unsigned long) c->sa_ike_life_seconds
				, (unsigned long) c->sa_ipsec_life_seconds
				, (unsigned long) c->sa_rekey_margin
				, (unsigned long) c->sa_rekey_fuzz
				, (unsigned long) c->sa_keying_tries);

			/* show DPD parameters if defined */

			if (c->dpd_action != DPD_ACTION_NONE)
				whack_log(RC_COMMENT
					, "\"%s\"%s:   dpd_action: %N;"
					" dpd_delay: %lus; dpd_timeout: %lus;"
					, c->name
					, instance
					, dpd_action_names, c->dpd_action
					, (unsigned long) c->dpd_delay
					, (unsigned long) c->dpd_timeout);

			if (c->policy_next)
			{
				whack_log(RC_COMMENT
					, "\"%s\"%s:   policy_next: %s"
					, c->name, instance, c->policy_next->name);
			}

			/* Note: we display key_from_DNS_on_demand as if policy [lr]KOD */
			fmt_policy_prio(c->prio, prio);
			whack_log(RC_COMMENT
				, "\"%s\"%s:   policy: %s%s%s; prio: %s; interface: %s; "
				, c->name
				, instance
				, prettypolicy(c->policy)
				, c->spd.this.key_from_DNS_on_demand? "+lKOD" : ""
				, c->spd.that.key_from_DNS_on_demand? "+rKOD" : ""
				, prio
				, ifn);
		}

		whack_log(RC_COMMENT
			, "\"%s\"%s:   newest ISAKMP SA: #%ld; newest IPsec SA: #%ld; "
			, c->name
			, instance
			, c->newest_isakmp_sa
			, c->newest_ipsec_sa);

		if (all)
		{
			ike_alg_show_connection(c, instance);
			kernel_alg_show_connection(c, instance);
		}
	}
	if (count > 0)
		whack_log(RC_COMMENT, BLANK_FORMAT);    /* spacer */

	free(array);
}

/* struct pending, the structure representing Quick Mode
 * negotiations delayed until a Keying Channel has been negotiated.
 * Essentially, a pending call to quick_outI1.
 */

struct pending {
	int whack_sock;
	struct state *isakmp_sa;
	connection_t *connection;
	lset_t policy;
	unsigned long try;
	so_serial_t replacing;

	struct pending *next;
};

/* queue a Quick Mode negotiation pending completion of a suitable Main Mode */
void add_pending(int whack_sock, struct state *isakmp_sa, connection_t *c,
				 lset_t policy, unsigned long try, so_serial_t replacing)
{
	bool already_queued = FALSE;
	struct pending *p = c->host_pair->pending;

	while (p)
	{
		if (streq(c->name, p->connection->name))
		{
			already_queued = TRUE;
			break;
		}
		p = p->next;
	}
	DBG(DBG_CONTROL,
		DBG_log("Queuing pending Quick Mode with %s \"%s\"%s"
				, ip_str(&c->spd.that.host_addr)
				, c->name
				, already_queued? " already done" : "")
	)
	if (already_queued)
		return;

	p = malloc_thing(struct pending);
	p->whack_sock = whack_sock;
	p->isakmp_sa = isakmp_sa;
	p->connection = c;
	p->policy = policy;
	p->try = try;
	p->replacing = replacing;
	p->next = c->host_pair->pending;
	c->host_pair->pending = p;
}

/* Release all the whacks awaiting the completion of this state.
 * This is accomplished by closing all the whack socket file descriptors.
 * We go to a lot of trouble to tell each whack, but to not tell it twice.
 */
void release_pending_whacks(struct state *st, err_t story)
{
	struct pending *p;
	struct stat stst;

	if (st->st_whack_sock == NULL_FD || fstat(st->st_whack_sock, &stst) != 0)
		zero(&stst);    /* resulting st_dev/st_ino ought to be distinct */

	release_whack(st);

	for (p = st->st_connection->host_pair->pending; p != NULL; p = p->next)
	{
		if (p->isakmp_sa == st && p->whack_sock != NULL_FD)
		{
			struct stat pst;

			if (fstat(p->whack_sock, &pst) == 0
			&& (stst.st_dev != pst.st_dev || stst.st_ino != pst.st_ino))
			{
				passert(whack_log_fd == NULL_FD);
				whack_log_fd = p->whack_sock;
				whack_log(RC_COMMENT
					, "%s for ISAKMP SA, but releasing whack for pending IPSEC SA"
					, story);
				whack_log_fd = NULL_FD;
			}
			close(p->whack_sock);
			p->whack_sock = NULL_FD;
		}
	}
}

static void delete_pending(struct pending **pp)
{
	struct pending *p = *pp;

	*pp = p->next;
	if (p->connection)
	{
		connection_discard(p->connection);
	}
	close_any(p->whack_sock);
	free(p);
}

void unpend(struct state *st)
{
	struct pending **pp
		, *p;

	for (pp = &st->st_connection->host_pair->pending; (p = *pp) != NULL; )
	{
		if (p->isakmp_sa == st)
		{
			DBG(DBG_CONTROL, DBG_log("unqueuing pending Quick Mode with %s \"%s\""
				, ip_str(&p->connection->spd.that.host_addr)
				, p->connection->name));
			(void) quick_outI1(p->whack_sock, st, p->connection, p->policy
				, p->try, p->replacing);
			p->whack_sock = NULL_FD;    /* ownership transferred */
			p->connection = NULL;       /* ownership transferred */
			delete_pending(pp);
		}
		else
		{
			pp = &p->next;
		}
	}
}

/* a Main Mode negotiation has been replaced; update any pending */
void update_pending(struct state *os, struct state *ns)
{
	struct pending *p;

	for (p = os->st_connection->host_pair->pending; p != NULL; p = p->next)
	{
		if (p->isakmp_sa == os)
			p->isakmp_sa = ns;
		if (p->connection->spd.this.host_port != ns->st_connection->spd.this.host_port)
		{
			p->connection->spd.this.host_port = ns->st_connection->spd.this.host_port;
			p->connection->spd.that.host_port = ns->st_connection->spd.that.host_port;
		}
	}
}

/* a Main Mode negotiation has failed; discard any pending */
void flush_pending_by_state(struct state *st)
{
	struct host_pair *hp = st->st_connection->host_pair;

	if (hp)
	{
		struct pending **pp
			, *p;

		for (pp = &hp->pending; (p = *pp) != NULL; )
		{
			if (p->isakmp_sa == st)
				delete_pending(pp);
			else
				pp = &p->next;
		}
	}
}

/* a connection has been deleted; discard any related pending */
static void flush_pending_by_connection(connection_t *c)
{
	if (c->host_pair)
	{
		struct pending **pp
			, *p;

		for (pp = &c->host_pair->pending; (p = *pp) != NULL; )
		{
			if (p->connection == c)
			{
				p->connection = NULL;   /* prevent delete_pending from releasing */
				delete_pending(pp);
			}
			else
			{
				pp = &p->next;
			}
		}
	}
}

void show_pending_phase2(const struct host_pair *hp, const struct state *st)
{
	const struct pending *p;

	for (p = hp->pending; p != NULL; p = p->next)
	{
		if (p->isakmp_sa == st)
		{
			/* connection-name state-number [replacing state-number] */
			char cip[CONN_INST_BUF];

			fmt_conn_instance(p->connection, cip);
			whack_log(RC_COMMENT, "#%lu: pending Phase 2 for \"%s\"%s replacing #%lu"
				, p->isakmp_sa->st_serialno
				, p->connection->name
				, cip
				, p->replacing);
		}
	}
}

/* Delete a connection if it is an instance and it is no longer in use.
 * We must be careful to avoid circularity:
 * we don't touch it if it is CK_GOING_AWAY.
 */
void connection_discard(connection_t *c)
{
	if (c->kind == CK_INSTANCE)
	{
		/* see if it is being used by a pending */
		struct pending *p;

		for (p = c->host_pair->pending; p != NULL; p = p->next)
			if (p->connection == c)
				return; /* in use, so we're done */

		if (!states_use_connection(c))
			delete_connection(c, FALSE);
	}
}


/* A template connection's eroute can be eclipsed by
 * either a %hold or an eroute for an instance iff
 * the template is a /32 -> /32.  This requires some special casing.
 */

long eclipse_count = 0;

connection_t *eclipsed(connection_t *c, struct spd_route **esrp)
{
	connection_t *ue;
	struct spd_route *sr1 = &c->spd;

	ue = NULL;

	while (sr1 && ue)
	{
		for (ue = connections; ue != NULL; ue = ue->ac_next)
		{
			struct spd_route *srue = &ue->spd;

			while (srue	&& srue->routing == RT_ROUTED_ECLIPSED
			&& !(samesubnet(&sr1->this.client, &srue->this.client)
				 && samesubnet(&sr1->that.client, &srue->that.client)))
			{
				srue = srue->next;
			}
			if (srue && srue->routing == RT_ROUTED_ECLIPSED)
			{
				*esrp = srue;
				break;
			}
		}
	}
	return ue;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
