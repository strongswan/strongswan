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

static void starter_stroke_add_end(stroke_msg_t *msg, stroke_end_t *msg_end, starter_end_t *conn_end)
{
	msg_end->id = push_string(msg, conn_end->id);
	msg_end->cert = push_string(msg, conn_end->cert);
	msg_end->ca = push_string(msg, conn_end->ca);
	msg_end->address = push_string(msg, inet_ntoa(conn_end->addr.u.v4.sin_addr));
	msg_end->subnet = push_string(msg, inet_ntoa(conn_end->subnet.addr.u.v4.sin_addr));
	msg_end->subnet_mask = conn_end->subnet.maskbits;
	msg_end->sendcert = conn_end->sendcert;
}

int starter_stroke_add_conn(starter_conn_t *conn)
{
	stroke_msg_t msg;

	msg.type = STR_ADD_CONN;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.add_conn.ikev2 = conn->keyexchange == KEY_EXCHANGE_IKEV2;
	msg.add_conn.name = push_string(&msg, connection_name(conn));
	msg.add_conn.rekey.ipsec_lifetime = conn->sa_ipsec_life_seconds;
	msg.add_conn.rekey.ike_lifetime = conn->sa_ike_life_seconds;
	msg.add_conn.rekey.margin = conn->sa_rekey_margin;
	msg.add_conn.rekey.tries = conn->sa_keying_tries;
	msg.add_conn.rekey.fuzz = conn->sa_rekey_fuzz;

	starter_stroke_add_end(&msg, &msg.add_conn.me, &conn->right);
	starter_stroke_add_end(&msg, &msg.add_conn.other, &conn->left);

	return send_stroke_msg(&msg);
}

int starter_stroke_del_conn(starter_conn_t *conn)
{
	stroke_msg_t msg;

	msg.type = STR_DEL_CONN;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.install.name = push_string(&msg, connection_name(conn));
	return send_stroke_msg(&msg);
}

int starter_stroke_route_conn(starter_conn_t *conn)
{
	stroke_msg_t msg;

	msg.type = STR_INSTALL;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.install.name = push_string(&msg, connection_name(conn));
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
