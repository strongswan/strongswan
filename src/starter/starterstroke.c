/* Stroke for charon is the counterpart to whack from pluto
 * Copyright (C) 2006 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <credentials/auth_cfg.h>

#include <freeswan.h>

#include <constants.h>
#include <defs.h>
#include <log.h>

#include <stroke_msg.h>

#include "starterstroke.h"
#include "confread.h"
#include "files.h"

#define IPV4_LEN	 4
#define IPV6_LEN	16

static char* push_string(stroke_msg_t *msg, char *string)
{
	unsigned long string_start = msg->length;

	if (string == NULL || msg->length + strlen(string) >= sizeof(stroke_msg_t))
	{
		return NULL;
	}
	else
	{
		msg->length += strlen(string) + 1;
		strcpy((char*)msg + string_start, string);
		return (char*)string_start;
	}
}

static int send_stroke_msg (stroke_msg_t *msg)
{
	struct sockaddr_un ctl_addr;
	int byte_count;
	char buffer[64];

	ctl_addr.sun_family = AF_UNIX;
	strcpy(ctl_addr.sun_path, CHARON_CTL_FILE);

	/* starter is not called from commandline, and therefore absolutely silent */
	msg->output_verbosity = -1;

	int sock = socket(AF_UNIX, SOCK_STREAM, 0);

	if (sock < 0)
	{
		plog("socket() failed: %s", strerror(errno));
		return -1;
	}
	if (connect(sock, (struct sockaddr *)&ctl_addr, offsetof(struct sockaddr_un, sun_path) + strlen(ctl_addr.sun_path)) < 0)
	{
		plog("connect(charon_ctl) failed: %s", strerror(errno));
		close(sock);
		return -1;
	}

	/* send message */
	if (write(sock, msg, msg->length) != msg->length)
	{
		plog("write(charon_ctl) failed: %s", strerror(errno));
		close(sock);
		return -1;
	}
	while ((byte_count = read(sock, buffer, sizeof(buffer)-1)) > 0)
	{
		buffer[byte_count] = '\0';
		plog("%s", buffer);
	}
	if (byte_count < 0)
	{
		plog("read() failed: %s", strerror(errno));
	}

	close(sock);
	return 0;
}

static char* connection_name(starter_conn_t *conn)
{
	 /* if connection name is '%auto', create a new name like conn_xxxxx */
	static char buf[32];

	if (streq(conn->name, "%auto"))
	{
		sprintf(buf, "conn_%lu", conn->id);
		return buf;
	}
	return conn->name;
}

static void ip_address2string(ip_address *addr, char *buffer, size_t len)
{
	switch (((struct sockaddr*)addr)->sa_family)
	{
		case AF_INET6:
		{
			struct sockaddr_in6* sin6 = (struct sockaddr_in6*)addr;
			u_int8_t zeroes[IPV6_LEN];

			memset(zeroes, 0, IPV6_LEN);
			if (memcmp(zeroes, &(sin6->sin6_addr.s6_addr), IPV6_LEN) &&
				inet_ntop(AF_INET6, &sin6->sin6_addr, buffer, len))
			{
				return;
			}
			snprintf(buffer, len, "%%any6");
			break;
		}
		case AF_INET:
		{
			struct sockaddr_in* sin = (struct sockaddr_in*)addr;
			u_int8_t zeroes[IPV4_LEN];

			memset(zeroes, 0, IPV4_LEN);
			if (memcmp(zeroes, &(sin->sin_addr.s_addr), IPV4_LEN) &&
				inet_ntop(AF_INET, &sin->sin_addr, buffer, len))
			{
				return;
			}
			/* fall through to default */
		}
		default:
			snprintf(buffer, len, "%%any");
			break;
	}
}

static void starter_stroke_add_end(stroke_msg_t *msg, stroke_end_t *msg_end, starter_end_t *conn_end)
{
	char buffer[INET6_ADDRSTRLEN];

	msg_end->auth = push_string(msg, conn_end->auth);
	msg_end->auth2 = push_string(msg, conn_end->auth2);
	msg_end->id = push_string(msg, conn_end->id);
	msg_end->id2 = push_string(msg, conn_end->id2);
	msg_end->rsakey = push_string(msg, conn_end->rsakey);
	msg_end->cert = push_string(msg, conn_end->cert);
	msg_end->cert2 = push_string(msg, conn_end->cert2);
	msg_end->cert_policy = push_string(msg, conn_end->cert_policy);
	msg_end->ca = push_string(msg, conn_end->ca);
	msg_end->ca2 = push_string(msg, conn_end->ca2);
	msg_end->groups = push_string(msg, conn_end->groups);
	msg_end->updown = push_string(msg, conn_end->updown);
	if (conn_end->host)
	{
		msg_end->address = push_string(msg, conn_end->host);
	}
	else
	{
		ip_address2string(&conn_end->addr, buffer, sizeof(buffer));
		msg_end->address = push_string(msg, buffer);
	}
	msg_end->ikeport = conn_end->ikeport;
	msg_end->subnets = push_string(msg, conn_end->subnet);
	msg_end->sourceip = push_string(msg, conn_end->sourceip);
	msg_end->sourceip_mask = conn_end->sourceip_mask;
	msg_end->sendcert = conn_end->sendcert;
	msg_end->hostaccess = conn_end->hostaccess;
	msg_end->tohost = !conn_end->has_client;
	msg_end->protocol = conn_end->protocol;
	msg_end->port = conn_end->port;
}

int starter_stroke_add_conn(starter_config_t *cfg, starter_conn_t *conn)
{
	stroke_msg_t msg;

	memset(&msg, 0, sizeof(msg));
	msg.type = STR_ADD_CONN;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.add_conn.ikev2 = conn->keyexchange != KEY_EXCHANGE_IKEV1;
	msg.add_conn.name = push_string(&msg, connection_name(conn));

	/* PUBKEY is preferred to PSK and EAP */
	if (conn->policy & POLICY_PUBKEY)
	{
		msg.add_conn.auth_method = AUTH_CLASS_PUBKEY;
	}
	else if (conn->policy & POLICY_PSK)
	{
		msg.add_conn.auth_method = AUTH_CLASS_PSK;
	}
	else if (conn->policy & POLICY_XAUTH_PSK)
	{
		msg.add_conn.auth_method = AUTH_CLASS_EAP;
	}
	else
	{
		msg.add_conn.auth_method = AUTH_CLASS_ANY;
	}
	msg.add_conn.eap_type = conn->eap_type;
	msg.add_conn.eap_vendor = conn->eap_vendor;
	msg.add_conn.eap_identity = push_string(&msg, conn->eap_identity);
	msg.add_conn.aaa_identity = push_string(&msg, conn->aaa_identity);

	if (conn->policy & POLICY_TUNNEL)
	{
		msg.add_conn.mode = MODE_TUNNEL;
	}
	else if (conn->policy & POLICY_BEET)
	{
		msg.add_conn.mode = MODE_BEET;
	}
	else if (conn->policy & POLICY_PROXY)
	{
		msg.add_conn.mode = MODE_TRANSPORT;
		msg.add_conn.proxy_mode = TRUE;
	}
	else if (conn->policy & POLICY_SHUNT_PASS)
	{
		msg.add_conn.mode = MODE_PASS;
	}
	else if (conn->policy & (POLICY_SHUNT_DROP | POLICY_SHUNT_REJECT))
	{
		msg.add_conn.mode = MODE_DROP;
	}
	else
	{
		msg.add_conn.mode = MODE_TRANSPORT;
	}

	if (!(conn->policy & POLICY_DONT_REKEY))
	{
		msg.add_conn.rekey.reauth = (conn->policy & POLICY_DONT_REAUTH) == LEMPTY;
		msg.add_conn.rekey.ipsec_lifetime = conn->sa_ipsec_life_seconds;
		msg.add_conn.rekey.ike_lifetime = conn->sa_ike_life_seconds;
		msg.add_conn.rekey.margin = conn->sa_rekey_margin;
		msg.add_conn.rekey.life_bytes = conn->sa_ipsec_life_bytes;
		msg.add_conn.rekey.margin_bytes = conn->sa_ipsec_margin_bytes;
		msg.add_conn.rekey.life_packets = conn->sa_ipsec_life_packets;
		msg.add_conn.rekey.margin_packets = conn->sa_ipsec_margin_packets;
		msg.add_conn.rekey.tries = conn->sa_keying_tries;
		msg.add_conn.rekey.fuzz = conn->sa_rekey_fuzz;
	}
	msg.add_conn.mobike = (conn->policy & POLICY_MOBIKE) != 0;
	msg.add_conn.force_encap = (conn->policy & POLICY_FORCE_ENCAP) != 0;
	msg.add_conn.ipcomp = (conn->policy & POLICY_COMPRESS) != 0;
	msg.add_conn.install_policy = conn->install_policy;
	msg.add_conn.crl_policy = cfg->setup.strictcrlpolicy;
	msg.add_conn.unique = cfg->setup.uniqueids;
	msg.add_conn.algorithms.ike = push_string(&msg, conn->ike);
	msg.add_conn.algorithms.esp = push_string(&msg, conn->esp);
	msg.add_conn.dpd.delay = conn->dpd_delay;
	msg.add_conn.dpd.action = conn->dpd_action;
	msg.add_conn.close_action = conn->close_action;
	msg.add_conn.inactivity = conn->inactivity;
	msg.add_conn.ikeme.mediation = conn->me_mediation;
	msg.add_conn.ikeme.mediated_by = push_string(&msg, conn->me_mediated_by);
	msg.add_conn.ikeme.peerid = push_string(&msg, conn->me_peerid);
	msg.add_conn.reqid = conn->reqid;
	msg.add_conn.mark_in.value = conn->mark_in.value;
	msg.add_conn.mark_in.mask = conn->mark_in.mask;
	msg.add_conn.mark_out.value = conn->mark_out.value;
	msg.add_conn.mark_out.mask = conn->mark_out.mask;
	msg.add_conn.tfc = conn->tfc;

	starter_stroke_add_end(&msg, &msg.add_conn.me, &conn->left);
	starter_stroke_add_end(&msg, &msg.add_conn.other, &conn->right);

	return send_stroke_msg(&msg);
}

int starter_stroke_del_conn(starter_conn_t *conn)
{
	stroke_msg_t msg;

	msg.type = STR_DEL_CONN;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.del_conn.name = push_string(&msg, connection_name(conn));
	return send_stroke_msg(&msg);
}

int starter_stroke_route_conn(starter_conn_t *conn)
{
	stroke_msg_t msg;

	msg.type = STR_ROUTE;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.route.name = push_string(&msg, connection_name(conn));
	return send_stroke_msg(&msg);
}

int starter_stroke_initiate_conn(starter_conn_t *conn)
{
	stroke_msg_t msg;

	msg.type = STR_INITIATE;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.initiate.name = push_string(&msg, connection_name(conn));
	return send_stroke_msg(&msg);
}

int starter_stroke_add_ca(starter_ca_t *ca)
{
	stroke_msg_t msg;

	msg.type = STR_ADD_CA;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.add_ca.name =        push_string(&msg, ca->name);
	msg.add_ca.cacert =      push_string(&msg, ca->cacert);
	msg.add_ca.crluri =      push_string(&msg, ca->crluri);
	msg.add_ca.crluri2 =     push_string(&msg, ca->crluri2);
	msg.add_ca.ocspuri =     push_string(&msg, ca->ocspuri);
	msg.add_ca.ocspuri2 =    push_string(&msg, ca->ocspuri2);
	msg.add_ca.certuribase = push_string(&msg, ca->certuribase);
	return send_stroke_msg(&msg);
}

int starter_stroke_del_ca(starter_ca_t *ca)
{
	stroke_msg_t msg;

	msg.type = STR_DEL_CA;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.del_ca.name = push_string(&msg, ca->name);
	return send_stroke_msg(&msg);
}

int starter_stroke_configure(starter_config_t *cfg)
{
	stroke_msg_t msg;

	if (cfg->setup.cachecrls)
	{
		msg.type = STR_CONFIG;
		msg.length = offsetof(stroke_msg_t, buffer);
		msg.config.cachecrl = 1;
		return send_stroke_msg(&msg);
	}
	return 0;
}

