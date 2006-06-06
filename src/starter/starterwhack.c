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
 *
 * RCSID $Id: starterwhack.c,v 1.17 2006/04/17 10:32:36 as Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/stddef.h>
#include <unistd.h>
#include <errno.h>

#include <freeswan.h>

#include <constants.h>
#include <defs.h>
#include <log.h>
#include <whack.h>

#include "starterwhack.h"
#include "confread.h"
#include "files.h"

static int
pack_str (char **p, char **next, char **roof)
{
    const char *s = (*p==NULL) ? "" : *p;    /* note: NULL becomes ""! */
    size_t len = strlen(s) + 1;

    if ((*roof - *next) < len)
    {
	return 0;	/* not enough space */
    }
    else
    {
	strcpy(*next, s);
	*next += len;
	*p = NULL;   /* don't send pointers on the wire! */
	return 1;
    }
}

static int
send_whack_msg (whack_message_t *msg)
{
    struct sockaddr_un ctl_addr = { AF_UNIX, PLUTO_CTL_FILE };
    int sock;
    ssize_t len;
    char *str_next, *str_roof;

    /* pack strings */
    str_next = (char *)msg->string;
    str_roof = (char *)&msg->string[sizeof(msg->string)];

    if (!pack_str(&msg->name,         &str_next, &str_roof)
    ||  !pack_str(&msg->left.id,      &str_next, &str_roof)
    ||  !pack_str(&msg->left.cert,    &str_next, &str_roof)
    ||  !pack_str(&msg->left.ca,      &str_next, &str_roof)
    ||  !pack_str(&msg->left.groups,  &str_next, &str_roof)
    ||  !pack_str(&msg->left.updown,  &str_next, &str_roof)
    ||  !pack_str(&msg->left.virt,    &str_next, &str_roof)
    ||  !pack_str(&msg->right.id,     &str_next, &str_roof)
    ||  !pack_str(&msg->right.cert,   &str_next, &str_roof)
    ||  !pack_str(&msg->right.ca,     &str_next, &str_roof)
    ||  !pack_str(&msg->right.groups, &str_next, &str_roof)
    ||  !pack_str(&msg->right.updown, &str_next, &str_roof)
    || !pack_str(&msg->right.virt,    &str_next, &str_roof)
    || !pack_str(&msg->keyid,         &str_next, &str_roof)
    || !pack_str(&msg->myid,          &str_next, &str_roof)
    || !pack_str(&msg->cacert,        &str_next, &str_roof)
    || !pack_str(&msg->ldaphost,      &str_next, &str_roof)
    || !pack_str(&msg->ldapbase,      &str_next, &str_roof)
    || !pack_str(&msg->crluri,        &str_next, &str_roof)
    || !pack_str(&msg->crluri2,       &str_next, &str_roof)
    || !pack_str(&msg->ocspuri,       &str_next, &str_roof)
    || !pack_str(&msg->ike,           &str_next, &str_roof)
    || !pack_str(&msg->esp,           &str_next, &str_roof)
    || !pack_str(&msg->sc_data,       &str_next, &str_roof)
    || (str_roof - str_next < msg->keyval.len))
    {
	plog("send_wack_msg(): can't pack strings");
	return -1;
    }
    if (msg->keyval.ptr)
	memcpy(str_next, msg->keyval.ptr, msg->keyval.len);
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

static void
init_whack_msg(whack_message_t *msg)
{
    memset(msg, 0, sizeof(whack_message_t));
    msg->magic = WHACK_MAGIC;
}

static char *
connection_name(starter_conn_t *conn)
{
    /* if connection name is '%auto', create a new name like conn_xxxxx */
    static char buf[32];

    if (streq(conn->name, "%auto"))
    {
	sprintf(buf, "conn_%ld", conn->id);
	return buf;
    }
    return conn->name;
}

static void
set_whack_end(whack_end_t *w, starter_end_t *end)
{
    w->id                  = end->id;
    w->cert                = end->cert;
    w->ca                  = end->ca;
    w->groups              = end->groups;
    w->host_addr           = end->addr;
    w->host_nexthop        = end->nexthop;
    w->host_srcip          = end->srcip;
    w->has_client          = end->has_client;

    if (w->has_client)
	w->client          = end->subnet;
    else
	w->client.addr.u.v4.sin_family = addrtypeof(&w->host_addr);

    w->has_client_wildcard = end->has_client_wildcard;
    w->has_port_wildcard   = end->has_port_wildcard;
    w->has_srcip           = end->has_srcip;
    w->modecfg             = end->modecfg;
    w->hostaccess          = end->hostaccess;
    w->sendcert            = end->sendcert;
    w->updown              = end->updown;
    w->host_port           = IKE_UDP_PORT;
    w->port                = end->port;
    w->protocol            = end->protocol;
    w->virt                = end->virt;

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
    whack_message_t msg;

    init_whack_msg(&msg);

    msg.whack_key = TRUE;
    msg.pubkey_alg = PUBKEY_ALG_RSA;
    if (end->id && end->rsakey)
    {
	/* special values to ignore */
	if (streq(end->rsakey, "")
	||  streq(end->rsakey, "%none")
	||  streq(end->rsakey, "%cert")
	||  streq(end->rsakey, "0x00"))
	{
	    return 0;
	}
	msg.keyid = end->id;
	err = atobytes(end->rsakey, 0, keyspace, sizeof(keyspace), &msg.keyval.len);
	if (err)
	{
	    plog("conn %s/%s: rsakey malformed [%s]", connection_name(conn), lr, err);
	    return 1;
	}
	else
	{
	    msg.keyval.ptr = keyspace;
	    return send_whack_msg(&msg);
	}
    }
    return 0;
}

int
starter_whack_add_conn(starter_conn_t *conn)
{
    whack_message_t msg;
    int r;

    init_whack_msg(&msg);

    msg.whack_connection = TRUE;
    msg.name = connection_name(conn);

    msg.ikev1                 = conn->keyexchange != KEY_EXCHANGE_IKEV2;
    msg.addr_family           = conn->addr_family;
    msg.tunnel_addr_family    = conn->tunnel_addr_family;
    msg.sa_ike_life_seconds   = conn->sa_ike_life_seconds;
    msg.sa_ipsec_life_seconds = conn->sa_ipsec_life_seconds;
    msg.sa_rekey_margin       = conn->sa_rekey_margin;
    msg.sa_rekey_fuzz         = conn->sa_rekey_fuzz;
    msg.sa_keying_tries       = conn->sa_keying_tries;
    msg.policy                = conn->policy;

    set_whack_end(&msg.left, &conn->left);
    set_whack_end(&msg.right, &conn->right);

    msg.esp = conn->esp;
    msg.ike = conn->ike;
    msg.pfsgroup = conn->pfsgroup;

    /* taken from pluto/whack.c */
    if (msg.pfsgroup)
    {
	char esp_buf[256];

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

    if (r == 0 && (conn->policy & POLICY_RSASIG))
    {
	r += starter_whack_add_pubkey (conn, &conn->left, "left");
	r += starter_whack_add_pubkey (conn, &conn->right, "right");
    }

    return r;
}

int
starter_whack_del_conn(starter_conn_t *conn)
{
    whack_message_t msg;

    init_whack_msg(&msg);
    msg.whack_delete = TRUE;
    msg.name = connection_name(conn);
    return send_whack_msg(&msg);
}

int
starter_whack_route_conn(starter_conn_t *conn)
{
    whack_message_t msg;

    init_whack_msg(&msg);
    msg.whack_route = TRUE;
    msg.name = connection_name(conn);
    return send_whack_msg(&msg);
}

int
starter_whack_initiate_conn(starter_conn_t *conn)
{
    whack_message_t msg;

    init_whack_msg(&msg);
    msg.whack_initiate = TRUE;
    msg.whack_async = TRUE;
    msg.name = connection_name(conn);
    return send_whack_msg(&msg);
}

int
starter_whack_listen(void)
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

int
starter_whack_add_ca(starter_ca_t *ca)
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

int
starter_whack_del_ca(starter_ca_t *ca)
{
    whack_message_t msg;

    init_whack_msg(&msg);

    msg.whack_delete = TRUE;
    msg.whack_ca     = TRUE;
    msg.name         = ca->name;

    return send_whack_msg(&msg);
}
