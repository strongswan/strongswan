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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <linux/stddef.h>

#include <types.h>

#include "stroke.h"
#include "stroke_keywords.h"

struct stroke_token {
    char *name;
    stroke_keyword_t kw;
};

static char* push_string(stroke_msg_t *msg, char *string)
{
	u_int string_start = msg->length;

	if (string == NULL ||  msg->length + strlen(string) >= sizeof(stroke_msg_t))
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
	struct sockaddr_un ctl_addr = { AF_UNIX, STROKE_SOCKET };
	int sock;
	char buffer[64];
	int byte_count;
	
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
	{
		fprintf(stderr, "Opening unix socket %s: %s\n", STROKE_SOCKET, strerror(errno));
		return -1;
	}
	if (connect(sock, (struct sockaddr *)&ctl_addr,
				offsetof(struct sockaddr_un, sun_path) + strlen(ctl_addr.sun_path)) < 0)
	{
		fprintf(stderr, "Connect to socket failed: %s\n", strerror(errno));
		close(sock);
		return -1;
	}
	
	/* send message */
	if (write(sock, msg, msg->length) != msg->length)
	{
		fprintf(stderr, "writing to socket failed: %s\n", strerror(errno));
		close(sock);
		return -1;
	}
	
	while ((byte_count = read(sock, buffer, sizeof(buffer)-1)) > 0)
	{
		buffer[byte_count] = '\0';
		printf("%s", buffer);
	}
	if (byte_count < 0)
	{
		fprintf(stderr, "reading from socket failed: %s\n", strerror(errno));
	}
	
	close(sock);
	return 0;
}

static int add_connection(char *name,
						  char *my_id, char *other_id, 
						  char *my_addr, char *other_addr,
						  char *my_net, char *other_net,
						  u_int my_netmask, u_int other_netmask)
{
	stroke_msg_t msg;
	
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.type = STR_ADD_CONN;
	
	msg.add_conn.name = push_string(&msg, name);
	msg.add_conn.ikev2 = 1;
	
	msg.add_conn.rekey.ipsec_lifetime = 0;
	msg.add_conn.rekey.ike_lifetime = 0;
	msg.add_conn.rekey.margin = 0;
	msg.add_conn.rekey.tries = 0;
	msg.add_conn.rekey.fuzz = 0;
	
	msg.add_conn.algorithms.ike = NULL;
	msg.add_conn.algorithms.esp = NULL;
	
	msg.add_conn.dpd.delay = 0;
	msg.add_conn.dpd.action = 1;
	
	msg.add_conn.me.id = push_string(&msg, my_id);
	msg.add_conn.me.address = push_string(&msg, my_addr);
	msg.add_conn.me.subnet = push_string(&msg, my_net);
	msg.add_conn.me.subnet_mask = my_netmask;
	msg.add_conn.me.cert = NULL;
	msg.add_conn.me.ca = NULL;
	msg.add_conn.me.sendcert = 1;
	msg.add_conn.me.hostaccess = FALSE;
	msg.add_conn.me.protocol = 0;
	msg.add_conn.me.port = 0;
	
	msg.add_conn.other.id = push_string(&msg, other_id);
	msg.add_conn.other.address = push_string(&msg, other_addr);
	msg.add_conn.other.subnet = push_string(&msg, other_net);
	msg.add_conn.other.subnet_mask = other_netmask;
	msg.add_conn.other.cert = NULL;
	msg.add_conn.other.ca = NULL;
	msg.add_conn.other.sendcert = 1;
	msg.add_conn.other.hostaccess = FALSE;
	msg.add_conn.other.protocol = 0;
	msg.add_conn.other.port = 0;
	
	return send_stroke_msg(&msg);
}

static int del_connection(char *name)
{
	stroke_msg_t msg;
	
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.type = STR_DEL_CONN;
	msg.initiate.name = push_string(&msg, name);
	return send_stroke_msg(&msg);
}

static int initiate_connection(char *name)
{
	stroke_msg_t msg;
	
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.type = STR_INITIATE;
	msg.initiate.name = push_string(&msg, name);
	return send_stroke_msg(&msg);
}

static int terminate_connection(char *name)
{
	stroke_msg_t msg;
	
	msg.type = STR_TERMINATE;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.initiate.name = push_string(&msg, name);
	return send_stroke_msg(&msg);
}

static int route_connection(char *name)
{
	stroke_msg_t msg;
	
	msg.type = STR_ROUTE;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.route.name = push_string(&msg, name);
	return send_stroke_msg(&msg);
}

static int unroute_connection(char *name)
{
	stroke_msg_t msg;
	
	msg.type = STR_UNROUTE;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.unroute.name = push_string(&msg, name);
	return send_stroke_msg(&msg);
}

static int show_status(stroke_keyword_t kw, char *connection)
{
	stroke_msg_t msg;
	
	msg.type = (kw == STROKE_STATUS)? STR_STATUS:STR_STATUS_ALL;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.status.name = push_string(&msg, connection);
	return send_stroke_msg(&msg);
}

static int list_flags[] = {
	LIST_CERTS,
	LIST_CACERTS,
	LIST_CRLS,
	LIST_ALL
};

static int list(stroke_keyword_t kw, bool utc)
{
	stroke_msg_t msg;
	
	msg.type = STR_LIST;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.list.utc = utc;
	msg.list.flags = list_flags[kw - STROKE_LIST_FIRST];
	return send_stroke_msg(&msg);
}

static int reread_flags[] = {
	REREAD_CACERTS,
	REREAD_CRLS,
	REREAD_ALL
};

static int reread(stroke_keyword_t kw)
{
	stroke_msg_t msg;
	
	msg.type = STR_REREAD;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.reread.flags = reread_flags[kw - STROKE_REREAD_FIRST];
	return send_stroke_msg(&msg);
}

static int set_logtype(char *context, char *type, int enable)
{
	stroke_msg_t msg;
	
	msg.type = STR_LOGTYPE;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.logtype.context = push_string(&msg, context);
	msg.logtype.type = push_string(&msg, type);
	msg.logtype.enable = enable;
	return send_stroke_msg(&msg);
}

static int set_loglevel(char *context, u_int level)
{
	stroke_msg_t msg;
	
	msg.type = STR_LOGLEVEL;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.loglevel.context = push_string(&msg, context);
	msg.loglevel.level = level;
	return send_stroke_msg(&msg);
}

static void exit_error(char *error)
{
	if (error)
	{
		fprintf(stderr, "%s\n", error);
	}
	exit(-1);
}

static void exit_usage(char *error)
{
	printf("Usage:\n");
	printf("  Add a connection:\n");
	printf("    stroke add NAME MY_ID OTHER_ID MY_ADDR OTHER_ADDR\\\n");
	printf("           MY_NET OTHER_NET MY_NETBITS OTHER_NETBITS\n");
	printf("    where: ID is any IKEv2 ID \n");
	printf("           ADDR is a IPv4 address\n");
	printf("           NET is a IPv4 address of the subnet to tunnel\n");
	printf("           NETBITS is the size of the subnet, as the \"24\" in 192.168.0.0/24\n");
	printf("  Delete a connection:\n");
	printf("    stroke delete NAME\n");
	printf("    where: NAME is a connection name added with \"stroke add\"\n");
	printf("  Initiate a connection:\n");
	printf("    stroke up NAME\n");
	printf("    where: NAME is a connection name added with \"stroke add\"\n");
	printf("  Terminate a connection:\n");
	printf("    stroke down NAME\n");
	printf("    where: NAME is a connection name added with \"stroke add\"\n");
	printf("  Set logtype for a logging context:\n");
	printf("    stroke logtype CONTEXT TYPE ENABLE\n");
	printf("    where: CONTEXT is PARSR|GNRAT|IKESA|SAMGR|CHDSA|MESSG|TPOOL|WORKR|SCHED|\n");
	printf("                      SENDR|RECVR|SOCKT|TESTR|DAEMN|CONFG|ENCPL|PAYLD\n");
	printf("           TYPE is CONTROL|ERROR|AUDIT|RAW|PRIVATE\n");
	printf("           ENABLE is 0|1\n");
	printf("  Set loglevel for a logging context:\n");
	printf("    stroke loglevel CONTEXT LEVEL\n");
	printf("    where: CONTEXT is PARSR|GNRAT|IKESA|SAMGR|CHDSA|MESSG|TPOOL|WORKR|SCHED|\n");
	printf("                      SENDR|RECVR|SOCKT|TESTR|DAEMN|CONFG|ENCPL|PAYLD\n");
	printf("           LEVEL is 0|1|2|3\n");
	printf("  Show connection status:\n");
	printf("    stroke status\n");
	printf("  Show list of locally loaded certificates and crls:\n");
	printf("    stroke listcerts|listcacerts|listcrls|listall\n");
	printf("  Reload ca certificates and crls:\n");
	printf("    stroke rereadcacerts|rereadcrls|rereadall\n");
	exit_error(error);
}

int main(int argc, char *argv[])
{
	const stroke_token_t *token;
	int res = 0;

	if (argc < 2)
	{
		exit_usage(NULL);
	}
	
	token = in_word_set(argv[1], strlen(argv[1]));

	if (token == NULL)
	{
		exit_usage("unknown keyword");
	}

	switch (token->kw)
	{
		case STROKE_ADD:
			if (argc < 11)
			{
				exit_usage("\"add\" needs more parameters...");
			}
			res = add_connection(argv[2],
								 argv[3], argv[4], 
								 argv[5], argv[6], 
								 argv[7], argv[8], 
								 atoi(argv[9]), atoi(argv[10]));
			break;
		case STROKE_DELETE:
		case STROKE_DEL:
			if (argc < 3)
			{
				exit_usage("\"delete\" needs a connection name");
			}
			res = del_connection(argv[2]);
			break;
		case STROKE_UP:
			if (argc < 3)
			{
				exit_usage("\"up\" needs a connection name");
			}
			res = initiate_connection(argv[2]);
			break;
		case STROKE_DOWN:
			if (argc < 3)
			{
				exit_usage("\"down\" needs a connection name");
			}
			res = terminate_connection(argv[2]);
			break;
		case STROKE_ROUTE:
			if (argc < 3)
			{
				exit_usage("\"route\" needs a connection name");
			}
			res = route_connection(argv[2]);
			break;
		case STROKE_UNROUTE:
			if (argc < 3)
			{
				exit_usage("\"unroute\" needs a connection name");
			}
			res = unroute_connection(argv[2]);
			break;
		case STROKE_LOGTYPE:
			if (argc < 5)
			{
				exit_usage("\"logtype\" needs more parameters...");
			}
			res = set_logtype(argv[2], argv[3], atoi(argv[4])); 
			break;
		case STROKE_LOGLEVEL:
			if (argc < 4)
			{
				exit_usage("\"logtype\" needs more parameters...");
			}
			res = set_loglevel(argv[2], atoi(argv[3])); 
			break;
		case STROKE_STATUS:
		case STROKE_STATUSALL:
			res = show_status(token->kw, argc > 2 ? argv[2] : NULL);
			break;
		case STROKE_LIST_CERTS:
		case STROKE_LIST_CACERTS:
		case STROKE_LIST_CRLS:
		case STROKE_LIST_ALL:
			res = list(token->kw, argc > 2 && streq(argv[2], "--utc"));
			break;
		case STROKE_REREAD_CACERTS:
		case STROKE_REREAD_CRLS:
		case STROKE_REREAD_ALL:
			res = reread(token->kw);
			break;
		default:
			exit_usage(NULL);
	}
	return res;
}
