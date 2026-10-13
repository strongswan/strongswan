/*
 * Copyright (C) 2026 Kristóf Havasi
 *
 * Copyright (C) secunet Security Networks AG
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

#define _GNU_SOURCE

#ifdef __linux__

#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int marker(char *helper, char *suffix)
{
	char path[PATH_MAX];
	int fd, length;

	length = snprintf(path, sizeof(path), "%s.%s", helper, suffix);
	if (length < 0 || length >= sizeof(path))
	{
		return -1;
	}
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
	if (fd < 0)
	{
		return -1;
	}
	if (dprintf(fd, "%d\n", (int)getpid()) < 0)
	{
		close(fd);
		return -1;
	}
	return close(fd);
}

/** This program is invoked only through the real EAP-GTC helper runner. */
int main(int argc, char *argv[])
{
	sigset_t mask;
	struct sigaction action;
	int signal;

	if ((argc != 5 && argc != 6) || strcmp(argv[1], "--ike-id") ||
		strcmp(argv[2], "42") || strcmp(argv[3], "--connection") ||
		strcmp(argv[4], "fortigate-test") ||
		(argc == 6 && strcmp(argv[5], "--push-capable")))
	{
		return 90;
	}
	if (sigprocmask(SIG_SETMASK, NULL, &mask) ||
		sigaction(SIGPIPE, NULL, &action) || action.sa_handler != SIG_DFL)
	{
		return 91;
	}
	for (signal = 1; signal < NSIG; signal++)
	{
		if (sigismember(&mask, signal) > 0)
		{
			return 92;
		}
	}
	if (argc == 6)
	{
		if (marker(argv[0], "ready"))
		{
			return 93;
		}
		kill(getpid(), SIGTERM);
		/* This marker proves whether SIGTERM failed to terminate the helper. */
		marker(argv[0], "returned");
		return 94;
	}
	return fputs("123456\n", stdout) < 0;
}

#else /* !__linux__ */

int main(void)
{
	return 77;
}

#endif /* __linux__ */
