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
 */

#include <sys/un.h>
#include <linux/stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <threads/stroke.h>

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

static int send_stroke_msg (stroke_msg_t *msg)
{
	struct sockaddr_un ctl_addr = { AF_UNIX, STROKE_SOCKET };
	int sock;
	
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
	{
		printf("Opening unix socket %s: %s\n", STROKE_SOCKET, strerror(errno));
		return -1;
	}
	if (connect(sock, (struct sockaddr *)&ctl_addr,
				offsetof(struct sockaddr_un, sun_path) + strlen(ctl_addr.sun_path)) < 0)
	{
		printf("Connect to socket failed: %s\n", strerror(errno));
		close(sock);
		return -1;
	}
	
	if (dup2(sock, 1) != 1)
	{
		printf("Unable to redirect socket output: %s\n", strerror(errno));
	}
	
	/* send message */
	if (write(sock, msg, msg->length) != msg->length)
	{
		printf("writing to socket failed: %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	close(sock);
	return 0;
}

static int add_connection(char *name,
				   char *my_id, char *other_id, 
				   char *my_addr, char *other_addr, 
				   char *my_net, char *other_net,
				   u_int8_t my_netmask, u_int8_t other_netmask)
{
	stroke_msg_t *msg = malloc(sizeof(stroke_msg_t));
	int res;
	
	msg->length = sizeof(stroke_msg_t);
	msg->type = STR_ADD_CONN;
	
	msg->add_conn.name = push_string(&msg, name);
	
	msg->add_conn.me.id = push_string(&msg, my_id);
	msg->add_conn.me.address = push_string(&msg, my_addr);
	msg->add_conn.me.subnet = push_string(&msg, my_net);
	msg->add_conn.me.subnet_mask = my_netmask;
	
	msg->add_conn.other.id = push_string(&msg, other_id);
	msg->add_conn.other.address = push_string(&msg, other_addr);
	msg->add_conn.other.subnet = push_string(&msg, other_net);
	msg->add_conn.other.subnet_mask = other_netmask;
	
	res = send_stroke_msg(msg);
	free(msg);
	return res;
}

static int initiate_connection(char *name)
{
	stroke_msg_t *msg = malloc(sizeof(stroke_msg_t));
	int res;
	
	msg->length = sizeof(stroke_msg_t);
	msg->type = STR_INITIATE;
	msg->initiate.name = push_string(&msg, name);
	res = send_stroke_msg(msg);
	free(msg);
	return res;
}

int main(int argc, char *argv[])
{
	add_connection("alice", NULL, NULL,
				   "192.168.0.1", "192.168.0.2",
				   "10.1.0.0", "10.2.0.0", 16, 16);
	
	add_connection("bob", "192.168.0.2", "192.168.0.1",
				   "192.168.0.2", "192.168.0.1",
				   "10.2.0.0", "10.1.0.0", 16, 16);
	
	if (argc == 2)
	{
		initiate_connection(argv[1]);
	}
	
	return 0;
}
