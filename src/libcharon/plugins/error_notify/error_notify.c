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

#include "error_notify_msg.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

/**
 * Example of a simple notification listener
 */
int main(int argc, char *argv[])
{
	struct sockaddr_un addr;
	error_notify_msg_t msg;
	int s;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, ERROR_NOTIFY_SOCKET);

	s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (s < 0)
	{
		fprintf(stderr, "opening socket failed: %s\n", strerror(errno));
		return 1;
	}
	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		fprintf(stderr, "connect failed: %s\n", strerror(errno));
		close(s);
		return 1;
	}
	while (1)
	{
		if (read(s, &msg, sizeof(msg)) != sizeof(msg))
		{
			fprintf(stderr, "read failed: %s\n", strerror(errno));
			close(s);
			return 1;
		}
		printf("%d %s %s %s %s\n",
			   msg.type, msg.name, msg.id, msg.ip, msg.str);
	}
	close(s);
	return 0;
}
