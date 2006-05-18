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

static char* push_string(stroke_msg_t **strm, char *string)
{
	stroke_msg_t *stroke_msg;
	size_t string_length;

	if (string == NULL)
	{
		return NULL;
	}
	stroke_msg = *strm;
	string_length = strlen(string) + 1;
	stroke_msg->length += string_length;

	stroke_msg = realloc(stroke_msg, stroke_msg->length);
	strcpy((char*)stroke_msg + stroke_msg->length - string_length, string);

	*strm = stroke_msg;
	return (char*)(u_int)stroke_msg->length - string_length;
}

static int
send_stroke_msg (stroke_msg_t *msg)
{
	struct sockaddr_un ctl_addr = { AF_UNIX, CHARON_CTL_FILE };
	int sock;
	int byte_count;
	char buffer[64];

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
	{
		plog("socket() failed: %s", strerror(errno));
		return -1;
	}
	if (connect(sock, (struct sockaddr *)&ctl_addr, 
		offsetof(struct sockaddr_un, sun_path) + strlen(ctl_addr.sun_path)) < 0)
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


int starter_stroke_add_conn(starter_conn_t *conn)
{
	stroke_msg_t *msg = malloc(sizeof(stroke_msg_t));
	int res;

	msg->length = sizeof(stroke_msg_t);
	msg->type = STR_ADD_CONN;

	msg->add_conn.name = push_string(&msg, connection_name(conn));

	msg->add_conn.me.id = push_string(&msg, conn->left.id);
	msg->add_conn.me.cert = push_string(&msg, conn->left.cert);
	msg->add_conn.me.address = push_string(&msg, inet_ntoa(conn->left.addr.u.v4.sin_addr));
	msg->add_conn.me.subnet = push_string(&msg, inet_ntoa(conn->left.subnet.addr.u.v4.sin_addr));
	msg->add_conn.me.subnet_mask = conn->left.subnet.maskbits;

	msg->add_conn.other.id = push_string(&msg, conn->right.id);
	msg->add_conn.other.cert = push_string(&msg, conn->right.cert);
	msg->add_conn.other.address = push_string(&msg, inet_ntoa(conn->right.addr.u.v4.sin_addr));
	msg->add_conn.other.subnet = push_string(&msg, inet_ntoa(conn->right.subnet.addr.u.v4.sin_addr));
	msg->add_conn.other.subnet_mask = conn->right.subnet.maskbits;

	res = send_stroke_msg(msg);
	free(msg);
	return res;
}

int starter_stroke_del_conn(starter_conn_t *conn)
{
	return 0;
}

int starter_stroke_route_conn(starter_conn_t *conn)
{
	stroke_msg_t *msg = malloc(sizeof(stroke_msg_t));
	int res;

	msg->length = sizeof(stroke_msg_t);
	msg->type = STR_INSTALL;
	msg->install.name = push_string(&msg, connection_name(conn));
	res = send_stroke_msg(msg);
	free(msg);
	return res;
}

int starter_stroke_initiate_conn(starter_conn_t *conn)
{
	stroke_msg_t *msg = malloc(sizeof(stroke_msg_t));
	int res;

	msg->length = sizeof(stroke_msg_t);
	msg->type = STR_INITIATE;
	msg->initiate.name = push_string(&msg, connection_name(conn));
	res = send_stroke_msg(msg);
	free(msg);
	return res;
}
