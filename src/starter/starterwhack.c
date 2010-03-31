/* strongSwan whack functions to communicate with pluto (whack.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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
#include <string.h>
#include <errno.h>

#include <freeswan.h>

#include <constants.h>
#include <defs.h>
#include <log.h>
#include <whack.h>

#include "starterwhack.h"
#include "confread.h"
#include "files.h"

#define ip_version(string)      (strchr(string, '.') ? AF_INET : AF_INET6)

static int pack_str (char **p, char **next, char **roof)
{
	const char *s = (*p==NULL) ? "" : *p;    /* note: NULL becomes ""! */
	size_t len = strlen(s) + 1;

	if ((*roof - *next) < len)
	{
		return 0;       /* not enough space */
	}
	else
	{
		strcpy(*next, s);
		*next += len;
		*p = NULL;   /* don't send pointers on the wire! */
		return 1;
	}
}

static int send_whack_msg (whack_message_t *msg)
{
	struct sockaddr_un ctl_addr;
	int sock;
	ssize_t len;
	char *str_next, *str_roof;

	ctl_addr.sun_family = AF_UNIX;
	strcpy(ctl_addr.sun_path, PLUTO_CTL_FILE);

	/* pack strings */
	str_next = (char *)msg->string;
	str_roof = (char *)&msg->string[sizeof(msg->string)];

	if (!pack_str(&msg->name,           &str_next, &str_roof)
	||  !pack_str(&msg->left.id,        &str_next, &str_roof)
	||  !pack_str(&msg->left.cert,      &str_next, &str_roof)
	||  !pack_str(&msg->left.ca,        &str_next, &str_roof)
	||  !pack_str(&msg->left.groups,    &str_next, &str_roof)
	||  !pack_str(&msg->left.updown,    &str_next, &str_roof)
	||  !pack_str(&msg->left.sourceip,  &str_next, &str_roof)
	||  !pack_str(&msg->left.virt,      &str_next, &str_roof)
	||  !pack_str(&msg->right.id,       &str_next, &str_roof)
	||  !pack_str(&msg->right.cert,     &str_next, &str_roof)
	||  !pack_str(&msg->right.ca,       &str_next, &str_roof)
	||  !pack_str(&msg->right.groups,   &str_next, &str_roof)
	||  !pack_str(&msg->right.updown,   &str_next, &str_roof)
	||  !pack_str(&msg->right.sourceip, &str_next, &str_roof)
	||  !pack_str(&msg->right.virt,     &str_next, &str_roof)
	||  !pack_str(&msg->keyid,          &str_next, &str_roof)
	||  !pack_str(&msg->myid,           &str_next, &str_roof)
	||  !pack_str(&msg->cacert,         &str_next, &str_roof)
	||  !pack_str(&msg->ldaphost,       &str_next, &str_roof)
	||  !pack_str(&msg->ldapbase,       &str_next, &str_roof)
	||  !pack_str(&msg->crluri,         &str_next, &str_roof)
	||  !pack_str(&msg->crluri2,        &str_next, &str_roof)
	||  !pack_str(&msg->ocspuri,        &str_next, &str_roof)
	||  !pack_str(&msg->ike,            &str_next, &str_roof)
	||  !pack_str(&msg->esp,            &str_next, &str_roof)
	||  !pack_str(&msg->sc_data,        &str_next, &str_roof)
	||  !pack_str(&msg->whack_lease_ip, &str_next, &str_roof)
	||  !pack_str(&msg->whack_lease_id, &str_next, &str_roof)
	||  (str_roof - str_next < msg->keyval.len))
	{
		plog("send_wack_msg(): can't pack strings");
		return -1;
	}
	if (msg->keyval.ptr)
	{
		memcpy(str_next, msg->keyval.ptr, msg->keyval.len);
	}
	msg->keyval.ptr = NULL;
	str_next += msg->keyval.len;
	len = str_next - (char *)msg;

	/* connect to pluto ctl */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
	{
		plog("socket() failed: %s", strerror(errno));
		return -1;
	}
	if (connect(sock, (struct sockaddr *)&ctl_addr,
		offsetof(struct sockaddr_un, sun_path) + strlen(ctl_addr.sun_path)) < 0)
	{
		plog("connect(pluto_ctl) failed: %s", strerror(errno));
		close(sock);
		return -1;
	}

	/* send message */
	if (write(sock, msg, len) != len)
	{
		plog("write(pluto_ctl) failed: %s", strerror(errno));
		close(sock);
		return -1;
	}

	/* TODO: read reply */
	close(sock);
	return 0;
}

static void init_whack_msg(whack_message_t *msg)
{
	memset(msg, 0, sizeof(whack_message_t));
	msg->magic = WHACK_MAGIC;
}

static char *connection_name(starter_conn_t *conn, char *buf, size_t size)
{
	/* if connection name is '%auto', create a new name like conn_xxxxx */
	if (streq(conn->name, "%auto"))
	{
		snprintf(buf, size, "conn_%ld", conn->id);
		return buf;
	}
	return conn->name;
}

static void set_whack_end(whack_end_t *w, starter_end_t *end, sa_family_t family)
{
	w->id                  = end->id;
	w->cert                = end->cert;
	w->ca                  = end->ca;
	w->groups              = end->groups;
	w->host_addr           = end->addr;
	w->has_client          = end->has_client;
	w->sourceip            = end->sourceip;
	w->sourceip_mask       = end->sourceip_mask;

	if (end->sourceip && end->sourceip_mask > 0)
	{
		ttoaddr(end->sourceip, 0, ip_version(end->sourceip), &w->host_srcip);
		w->has_srcip = !end->has_natip;
	}
	else
	{
		anyaddr(AF_INET, &w->host_srcip);
	}

	if (family == AF_INET6 && isanyaddr(&end->nexthop))
	{
		anyaddr(AF_INET6, &end->nexthop);
	}
	w->host_nexthop        = end->nexthop;

	if (w->has_client)
	{
		char *pos;
		int len = 0;

		pos = strchr(end->subnet, ',');
		if (pos)
		{
			len = pos - end->subnet;
		}
		ttosubnet(end->subnet, len, ip_version(end->subnet), &w->client);
	}
	else
	{
		if (end->has_virt)
		{
			w->virt = end->subnet;
		}
		w->client.addr.u.v4.sin_family = addrtypeof(&w->host_addr);
	}

	w->has_client_wildcard = end->has_client_wildcard;
	w->has_port_wildcard   = end->has_port_wildcard;
	w->has_natip           = end->has_natip;
	w->allow_any           = end->allow_any && !end->dns_failed;
	w->modecfg             = end->modecfg;
	w->hostaccess          = end->hostaccess;
	w->sendcert            = end->sendcert;
	w->updown              = end->updown;
	w->host_port           = IKE_UDP_PORT;
	w->port                = end->port;
	w->protocol            = end->protocol;

	if (w->port != 0)
	{
		int port = htons(w->port);

		setportof(port, &w->host_addr);
		setportof(port, &w->client.addr);
	}
}

static int
starter_whack_add_pubkey (starter_conn_t *conn, starter_end_t *end
, const char *lr)
{
	const char *err;
	static char keyspace[1024 + 4];
	char buf[ADDRTOT_BUF], name[32];
	whack_message_t msg;

	init_whack_msg(&msg);
	connection_name(conn, name, sizeof(name));

	msg.whack_key = TRUE;
	msg.pubkey_alg = PUBKEY_ALG_RSA;
	if (end->rsakey)
	{
		/* special values to ignore */
		if (streq(end->rsakey, "")
		||  streq(end->rsakey, "%none")
		||  streq(end->rsakey, "%cert")
		||  streq(end->rsakey, "0x00"))
		{
			return 0;
		}
		err = atobytes(end->rsakey, 0, keyspace, sizeof(keyspace), &msg.keyval.len);
		if (err)
		{
			plog("conn %s/%s: rsakey malformed [%s]", name, lr, err);
			return 1;
		}
		if (end->id)
		{
			msg.keyid = end->id;
		}
		else
		{
			addrtot(&end->addr, 0, buf, sizeof(buf));
			msg.keyid = buf;
		}
		msg.keyval.ptr = keyspace;
		return send_whack_msg(&msg);
	}
	return 0;
}

int starter_whack_add_conn(starter_conn_t *conn)
{
	char esp_buf[256], name[32];
	whack_message_t msg;
	int r;

	init_whack_msg(&msg);

	msg.whack_connection = TRUE;
	msg.name = connection_name(conn, name, sizeof(name));

	msg.ikev1                 = conn->keyexchange != KEY_EXCHANGE_IKEV2;
	msg.addr_family           = conn->addr_family;
	msg.tunnel_addr_family    = conn->tunnel_addr_family;
	msg.sa_ike_life_seconds   = conn->sa_ike_life_seconds;
	msg.sa_ipsec_life_seconds = conn->sa_ipsec_life_seconds;
	msg.sa_rekey_margin       = conn->sa_rekey_margin;
	msg.sa_rekey_fuzz         = conn->sa_rekey_fuzz;
	msg.sa_keying_tries       = conn->sa_keying_tries;
	msg.policy                = conn->policy;

	/*
	 * Make sure the IKEv2-only policy bits are unset for IKEv1 connections
	 */
	msg.policy &= ~POLICY_DONT_REAUTH;
	msg.policy &= ~POLICY_BEET;
	msg.policy &= ~POLICY_MOBIKE;
	msg.policy &= ~POLICY_FORCE_ENCAP;

	set_whack_end(&msg.left, &conn->left, conn->addr_family);
	set_whack_end(&msg.right, &conn->right, conn->addr_family);

	msg.esp = conn->esp;
	msg.ike = conn->ike;
	msg.pfsgroup = conn->pfsgroup;

	/* taken from pluto/whack.c */
	if (msg.pfsgroup)
	{
		snprintf(esp_buf, sizeof (esp_buf), "%s;%s"
				   , msg.esp ? msg.esp : ""
				   , msg.pfsgroup ? msg.pfsgroup : "");
		msg.esp = esp_buf;

		DBG(DBG_CONTROL,
			DBG_log("Setting --esp=%s", msg.esp)
		)
	}
	msg.dpd_delay   = conn->dpd_delay;
	msg.dpd_timeout = conn->dpd_timeout;
	msg.dpd_action  = conn->dpd_action;
/*  msg.dpd_count = conn->dpd_count; not supported yet by strongSwan */

	r =  send_whack_msg(&msg);

	if (r == 0 && (conn->policy & POLICY_PUBKEY))
	{
		r += starter_whack_add_pubkey (conn, &conn->left, "left");
		r += starter_whack_add_pubkey (conn, &conn->right, "right");
	}

	return r;
}

int starter_whack_del_conn(starter_conn_t *conn)
{
	char name[32];
	whack_message_t msg;

	init_whack_msg(&msg);
	msg.whack_delete = TRUE;
	msg.name = connection_name(conn, name, sizeof(name));
	return send_whack_msg(&msg);
}

int starter_whack_route_conn(starter_conn_t *conn)
{
	char name[32];
	whack_message_t msg;

	init_whack_msg(&msg);
	msg.whack_route = TRUE;
	msg.name = connection_name(conn, name, sizeof(name));
	return send_whack_msg(&msg);
}

int starter_whack_initiate_conn(starter_conn_t *conn)
{
	char name[32];
	whack_message_t msg;

	init_whack_msg(&msg);
	msg.whack_initiate = TRUE;
	msg.whack_async = TRUE;
	msg.name = connection_name(conn, name, sizeof(name));
	return send_whack_msg(&msg);
}

int starter_whack_listen(void)
{
	whack_message_t msg;
	init_whack_msg(&msg);
	msg.whack_listen = TRUE;
	return send_whack_msg(&msg);
}

int starter_whack_shutdown(void)
{
	whack_message_t msg;

	init_whack_msg(&msg);
	msg.whack_shutdown = TRUE;
	return send_whack_msg(&msg);
}

int starter_whack_add_ca(starter_ca_t *ca)
{
	whack_message_t msg;

	init_whack_msg(&msg);

	msg.whack_ca     = TRUE;
	msg.name         = ca->name;
	msg.cacert       = ca->cacert;
	msg.ldaphost     = ca->ldaphost;
	msg.ldapbase     = ca->ldapbase;
	msg.crluri       = ca->crluri;
	msg.crluri2      = ca->crluri2;
	msg.ocspuri      = ca->ocspuri;
	msg.whack_strict = ca->strict;

	return send_whack_msg(&msg);
}

int starter_whack_del_ca(starter_ca_t *ca)
{
	whack_message_t msg;

	init_whack_msg(&msg);

	msg.whack_delete = TRUE;
	msg.whack_ca     = TRUE;
	msg.name         = ca->name;

	return send_whack_msg(&msg);
}
