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

#include "stroke.h"

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
						  char *my_cert, char *other_cert,
						  char *my_addr, char *other_addr,
						  char *my_net, char *other_net,
						  u_int my_netmask, u_int other_netmask)
{
	stroke_msg_t *msg = malloc(sizeof(stroke_msg_t));
	int res;
	
	msg->length = sizeof(stroke_msg_t);
	msg->type = STR_ADD_CONN;
	
	msg->add_conn.name = push_string(&msg, name);
	
	msg->add_conn.me.id = push_string(&msg, my_id);
	msg->add_conn.me.cert = push_string(&msg, my_cert);
	msg->add_conn.me.address = push_string(&msg, my_addr);
	msg->add_conn.me.subnet = push_string(&msg, my_net);
	msg->add_conn.me.subnet_mask = my_netmask;
	
	msg->add_conn.other.id = push_string(&msg, other_id);
	msg->add_conn.other.cert = push_string(&msg, other_cert);
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

static int terminate_connection(char *name)
{
	stroke_msg_t *msg = malloc(sizeof(stroke_msg_t));
	int res;
	
	msg->length = sizeof(stroke_msg_t);
	msg->type = STR_TERMINATE;
	msg->initiate.name = push_string(&msg, name);
	res = send_stroke_msg(msg);
	free(msg);
	return res;
}

static int show_status()
{
	stroke_msg_t *msg = malloc(sizeof(stroke_msg_t));
	int res;
	
	msg->length = sizeof(stroke_msg_t);
	msg->type = STR_STATUS;
	res = send_stroke_msg(msg);
	free(msg);
	return res;
}

static int set_logtype(char *context, char *type, int enable)
{
	stroke_msg_t *msg = malloc(sizeof(stroke_msg_t));
	int res;
	
	msg->length = sizeof(stroke_msg_t);
	msg->type = STR_LOGTYPE;
	msg->logtype.context = push_string(&msg, context);
	msg->logtype.type = push_string(&msg, type);
	msg->logtype.enable = enable;
	res = send_stroke_msg(msg);
	free(msg);
	return res;
}

static int set_loglevel(char *context, u_int level)
{
	stroke_msg_t *msg = malloc(sizeof(stroke_msg_t));
	int res;
	
	msg->length = sizeof(stroke_msg_t);
	msg->type = STR_LOGLEVEL;
	msg->loglevel.context = push_string(&msg, context);
	msg->loglevel.level = level;
	res = send_stroke_msg(msg);
	free(msg);
	return res;
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
	printf("    stroke add NAME MY_ID OTHER_ID MY_CERT OTHER_CERT\\\n");
	printf("           MY_ADDR OTHER_ADDR MY_NET OTHER_NET\\\n");
	printf("           MY_NETBITS OTHER_NETBITS\n");
	printf("    where: ID is any IKEv2 ID (currently only IPv4 adresses\n");
	printf("           CERT is a certificate filename\n");
	printf("           ADDR is a IPv4 address\n");
	printf("           NET is a IPv4 address of the subnet to tunnel\n");
	printf("           NETBITS is the size of the subnet, as the \"24\" in 192.168.0.0/24\n");
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
	exit_error(error);
}

int main(int argc, char *argv[])
{
	int res;
	
	if (argc < 2)
	{
		exit_usage(NULL);
	}
	
	if (strcmp(argv[1], "status") == 0 || 
		strcmp(argv[1], "statusall") == 0)
	{
		res = show_status();
	}
	
	else if (strcmp(argv[1], "up") == 0)
	{
		if (argc < 3)
		{
			exit_usage("\"up\" needs a connection name");
		}
		res = initiate_connection(argv[2]);
	}
	else if (strcmp(argv[1], "down") == 0)
	{
		if (argc < 3)
		{
			exit_usage("\"down\" needs a connection name");
		}
		res = terminate_connection(argv[2]);
	}
	else if (strcmp(argv[1], "add") == 0)
	{
		if (argc < 13)
		{
			exit_usage("\"add\" needs more parameters...");
		}
		res = add_connection(argv[2],
							 argv[3], argv[4], 
							 argv[5], argv[6], 
							 argv[7], argv[8], 
							 argv[9], argv[10], 
							 atoi(argv[11]), atoi(argv[12])); 
	}
	else if (strcmp(argv[1], "logtype") == 0)
	{
		if (argc < 5)
		{
			exit_usage("\"logtype\" needs more parameters...");
		}
		res = set_logtype(argv[2], argv[3], atoi(argv[4])); 
	}
	else if (strcmp(argv[1], "loglevel") == 0)
	{
		if (argc < 4)
		{
			exit_usage("\"logtype\" needs more parameters...");
		}
		res = set_loglevel(argv[2], atoi(argv[3])); 
	}
	else
	{
		exit_usage(NULL);
	}
	
	if (res)
	{
		exit_error("communication with charon failed!\n");
	}
	return 0;
}
