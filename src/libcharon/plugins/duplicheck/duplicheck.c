/*
 * Copyright (C) 2011 Martin Willi
 * Copyright (C) 2011 revosec AG
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

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>

#define DUPLICHECK_SOCKET IPSEC_PIDDIR "/charon.dck"

int main(int argc, char *argv[])
{
	struct sockaddr_un addr;
	char buf[128];
	int fd, len;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, DUPLICHECK_SOCKET);

	fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd < 0)
	{
		fprintf(stderr, "opening socket failed: %s\n", strerror(errno));
		return 1;
	}
	if (connect(fd, (struct sockaddr *)&addr,
			offsetof(struct sockaddr_un, sun_path) + strlen(addr.sun_path)) < 0)
	{
		fprintf(stderr, "connecting to %s failed: %s\n",
				DUPLICHECK_SOCKET, strerror(errno));
		close(fd);
		return 1;
	}
	while (1)
	{
		len = recv(fd, &buf, sizeof(buf) - 1, 0);
		if (len < 0)
		{
			fprintf(stderr, "reading from socket failed: %s\n", strerror(errno));
			close(fd);
			return 1;
		}
		printf("%.*s\n", len, buf);
	}
}
