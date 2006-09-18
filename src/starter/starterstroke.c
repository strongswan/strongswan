/* Stroke for charon is the counterpart to whack from pluto
 * Copyright (C) 2006 Martin Willi - Hochschule fuer Technik Rapperswil
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
 * RCSID $Id: starterstroke.c $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <freeswan.h>

#include <constants.h>
#include <defs.h>
#include <log.h>

#include <stroke.h>

#include "starterstroke.h"
#include "confread.h"
#include "files.h"

/**
 * AUTH Method to use.
 * 
 * @ingroup config
 */
enum auth_method_t {
	/**
	 * Computed as specified in section 2.15 of RFC using 
	 * an RSA private key over a PKCS#1 padded hash.
	 */
	RSA_DIGITAL_SIGNATURE = 1,
	
	/** 
	 * Computed as specified in section 2.15 of RFC using the 
	 * shared key associated with the identity in the ID payload 
	 * and the negotiated prf function
	 */
	SHARED_KEY_MESSAGE_INTEGRITY_CODE = 2,
	
	/**
	 * Computed as specified in section 2.15 of RFC using a 
	 * DSS private key over a SHA-1 hash.
	 */
	DSS_DIGITAL_SIGNATURE = 3,
};

static char* push_string(stroke_msg_t *msg, char *string)
{
	u_int string_start = msg->length;

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
	struct sockaddr_un ctl_addr = { AF_UNIX, CHARON_CTL_FILE };
	int byte_count;
	char buffer[64];

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
		sprintf(buf, "conn_%ld", conn->id);
		return buf;
	}
	return conn->name;
}

static void ip_address2string(ip_address *addr, char *buffer, size_t len)
{
	switch (((struct sockaddr*)addr)->sa_family)
	{
		case AF_INET:
		{
			struct sockaddr_in* sin = (struct sockaddr_in*)addr;
			if (inet_ntop(AF_INET, &sin->sin_addr, buffer, len))
			{
				return;
			}
			break;
		}
		case AF_INET6:
		{
			struct sockaddr_in6* sin6 = (struct sockaddr_in6*)addr;
			if (inet_ntop(AF_INET6, &sin6->sin6_addr, buffer, len))
			{
				return;
			}
			break;
		}
		default:
			break;
	}
	/* failed */
	snprintf(buffer, len, "0.0.0.0");
}


static void starter_stroke_add_end(stroke_msg_t *msg, stroke_end_t *msg_end, starter_end_t *conn_end)
{
	char buffer[INET6_ADDRSTRLEN];
	
	msg_end->id = push_string(msg, conn_end->id);
	msg_end->cert = push_string(msg, conn_end->cert);
	msg_end->ca = push_string(msg, conn_end->ca);
	msg_end->updown = push_string(msg, conn_end->updown);
	ip_address2string(&conn_end->addr, buffer, sizeof(buffer));
	msg_end->address = push_string(msg, buffer);
	ip_address2string(&conn_end->subnet.addr, buffer, sizeof(buffer));
	msg_end->subnet = push_string(msg, buffer);
	msg_end->subnet_mask = conn_end->subnet.maskbits;
	msg_end->sendcert = conn_end->sendcert;
	msg_end->protocol = conn_end->protocol;
	msg_end->port = conn_end->port;
}

int starter_stroke_add_conn(starter_conn_t *conn)
{
	stroke_msg_t msg;

	msg.type = STR_ADD_CONN;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.add_conn.ikev2 = conn->keyexchange == KEY_EXCHANGE_IKEV2;
	msg.add_conn.name = push_string(&msg, connection_name(conn));
	msg.add_conn.auth_method = (conn->policy & POLICY_PSK)?
		SHARED_KEY_MESSAGE_INTEGRITY_CODE : RSA_DIGITAL_SIGNATURE;
 
	if (conn->policy & POLICY_DONT_REKEY)
	{
		msg.add_conn.rekey.ipsec_lifetime = 0;
		msg.add_conn.rekey.ike_lifetime = 0;
		msg.add_conn.rekey.margin = 0;
		msg.add_conn.rekey.tries = 0;
		msg.add_conn.rekey.fuzz = 0;
	}
	else
	{
		msg.add_conn.rekey.ipsec_lifetime = conn->sa_ipsec_life_seconds;
		msg.add_conn.rekey.ike_lifetime = conn->sa_ike_life_seconds;
		msg.add_conn.rekey.margin = conn->sa_rekey_margin;
		msg.add_conn.rekey.tries = conn->sa_keying_tries;
		msg.add_conn.rekey.fuzz = conn->sa_rekey_fuzz;
	}
	msg.add_conn.algorithms.ike = push_string(&msg, conn->ike);
	msg.add_conn.algorithms.esp = push_string(&msg, conn->esp);
	msg.add_conn.dpd.delay = conn->dpd_delay;
	msg.add_conn.dpd.action = conn->dpd_action;

	starter_stroke_add_end(&msg, &msg.add_conn.me, &conn->right);
	starter_stroke_add_end(&msg, &msg.add_conn.other, &conn->left);

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
