/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "lookip_msg.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>

/**
 * Connect to the daemon, return FD
 */
static int make_connection()
{
	struct sockaddr_un addr;
	int fd;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, LOOKIP_SOCKET);

	fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd < 0)
	{
		fprintf(stderr, "opening socket failed: %s\n", strerror(errno));
		return -1;
	}
	if (connect(fd, (struct sockaddr *)&addr,
			offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path)) < 0)
	{
		fprintf(stderr, "connecting to %s failed: %s\n",
				LOOKIP_SOCKET, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

/**
 * Send a request message
 */
static int send_request(int fd, int type, char *vip)
{
	lookip_request_t req = {
		.type = type,
	};

	if (vip)
	{
		snprintf(req.vip, sizeof(req.vip), "%s", vip);
	}
	if (send(fd, &req, sizeof(req), 0) != sizeof(req))
	{
		fprintf(stderr, "writing to socket failed: %s\n", strerror(errno));
		return 2;
	}
	return 0;
}

/**
 * Receive entries from fd. If block is != 0, the call blocks until closed
 */
static int receive(int fd, int block, int loop)
{
	lookip_response_t resp;
	char *label, name[32];
	int res;

	do
	{
		res = recv(fd, &resp, sizeof(resp), block ? 0 : MSG_DONTWAIT);
		if (res == 0)
		{	/* closed by server */
			return 0;
		}
		if (res != sizeof(resp))
		{
			if (!block && (errno == EAGAIN || errno == EWOULDBLOCK))
			{	/* call would block, but we don't */
				return 0;
			}
			fprintf(stderr, "reading from socket failed: %s\n", strerror(errno));
			return 1;
		}
		switch (resp.type)
		{
			case LOOKIP_ENTRY:
				label = "lookup:";
				break;
			case LOOKIP_NOT_FOUND:
				label = "not found:";
				break;
			case LOOKIP_NOTIFY_UP:
				label = "up:";
				break;
			case LOOKIP_NOTIFY_DOWN:
				label = "down:";
				break;
			default:
				fprintf(stderr, "received invalid message type: %d\n", resp.type);
				return 1;
		}
		resp.vip[sizeof(resp.vip) - 1] = '\0';
		resp.ip[sizeof(resp.ip) - 1] = '\0';
		resp.id[sizeof(resp.id) - 1] = '\0';
		resp.name[sizeof(resp.name) - 1] = '\0';

		snprintf(name, sizeof(name), "%s[%u]", resp.name, resp.unique_id);
		printf("%-12s %16s %16s %20s %s\n",
			   label, resp.vip, resp.ip, name, resp.id);
	}
	while (loop);

	return 0;
}

/**
 * Interactive IP lookup shell
 */
static int interactive(int fd)
{
	printf("Enter IP address or 'quit'\n");

	while (1)
	{
		char line[64], *pos;
		int res;

		printf("> ");
		fflush(stdout);

		if (fgets(line, sizeof(line), stdin))
		{
			pos = strchr(line, '\n');
			if (pos)
			{
				*pos = '\0';
			}
			if (strlen(line) == 0)
			{
				continue;
			}
			if (strcmp(line, "quit") == 0)
			{
				return send_request(fd, LOOKIP_END, NULL);
			}
			res = send_request(fd, LOOKIP_LOOKUP, line);
			if (res != 0)
			{
				return res;
			}
			res = receive(fd, 1, 0);
			if (res != 0)
			{
				return res;
			}
		}
	}
}

/**
 * Print usage information
 */
static void usage(char *cmd)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s --help\n", cmd);
	fprintf(stderr, "  %s --dump\n", cmd);
	fprintf(stderr, "  %s --lookup <IP>\n", cmd);
	fprintf(stderr, "  %s --listen-up\n", cmd);
	fprintf(stderr, "  %s --listen-down\n", cmd);
	fprintf(stderr, "Any combination of options is allowed.\n");
}

int main(int argc, char *argv[])
{
	int fd, res = 0, end = 0;
	struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "dump", no_argument, NULL, 'd' },
		{ "lookup", required_argument, NULL, 'l' },
		{ "listen-up", no_argument, NULL, 'u' },
		{ "listen-down", no_argument, NULL, 'c' },
		{ 0,0,0,0 }
	};

	fd = make_connection();
	if (fd == -1)
	{
		return 1;
	}

	if (argc == 1)
	{
		res = interactive(fd);
		close(fd);
		return res;
	}

	while (res == 0)
	{
		switch (getopt_long(argc, argv, "", long_opts, NULL))
		{
			case EOF:
				end = 1;
				break;
			case 'h':
				usage(argv[0]);
				break;
			case 'd':
				res = send_request(fd, LOOKIP_DUMP, NULL);
				break;
			case 'l':
				res = send_request(fd, LOOKIP_LOOKUP, optarg);
				break;
			case 'u':
				res = send_request(fd, LOOKIP_REGISTER_UP, NULL);
				break;
			case 'c':
				res = send_request(fd, LOOKIP_REGISTER_DOWN, NULL);
				break;
			default:
				usage(argv[0]);
				res = 1;
				break;
		}
		if (end)
		{
			break;
		}
		if (res == 0)
		{	/* read all currently available results */
			res = receive(fd, 0, 1);
		}
	}
	if (res == 0)
	{
		/* send close message */
		send_request(fd, LOOKIP_END, NULL);
		/* read until socket gets closed */
		res = receive(fd, 1, 1);
	}
	close(fd);

	return res;
}
