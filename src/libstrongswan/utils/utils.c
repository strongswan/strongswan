/*
 * Copyright (C) 2008-2014 Tobias Brunner
 * Copyright (C) 2005-2008 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#include "utils.h"

#include <unistd.h>
#include <limits.h>
#ifndef WIN32
# include <signal.h>
#endif

#include <library.h>
#include <collections/enumerator.h>

#ifdef WIN32

#include <threading/mutex.h>
#include <threading/condvar.h>

/**
 * Flag to indicate signaled wait_sigint()
 */
static bool sigint_signaled = FALSE;

/**
 * Condvar to wait in wait_sigint()
 */
static condvar_t *sigint_cond;

/**
 * Mutex to check signaling()
 */
static mutex_t *sigint_mutex;

/**
 * Control handler to catch ^C
 */
static BOOL WINAPI handler(DWORD dwCtrlType)
{
	switch (dwCtrlType)
	{
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
		case CTRL_CLOSE_EVENT:
			sigint_mutex->lock(sigint_mutex);
			sigint_signaled = TRUE;
			sigint_cond->signal(sigint_cond);
			sigint_mutex->unlock(sigint_mutex);
			return TRUE;
		default:
			return FALSE;
	}
}

/**
 * Windows variant
 */
void wait_sigint()
{
	SetConsoleCtrlHandler(handler, TRUE);

	sigint_mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	sigint_cond = condvar_create(CONDVAR_TYPE_DEFAULT);

	sigint_mutex->lock(sigint_mutex);
	while (!sigint_signaled)
	{
		sigint_cond->wait(sigint_cond, sigint_mutex);
	}
	sigint_mutex->unlock(sigint_mutex);

	sigint_mutex->destroy(sigint_mutex);
	sigint_cond->destroy(sigint_cond);
}

#else /* !WIN32 */

/**
 * Unix variant
 */
void wait_sigint()
{
	sigset_t set;
	int sig;

	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);

	sigprocmask(SIG_BLOCK, &set, NULL);
	sigwait(&set, &sig);
}

#endif

#ifndef HAVE_CLOSEFROM
/**
 * Described in header.
 */
void closefrom(int lowfd)
{
	char fd_dir[PATH_MAX];
	int maxfd, fd, len;

	/* try to close only open file descriptors on Linux... */
	len = snprintf(fd_dir, sizeof(fd_dir), "/proc/%u/fd", getpid());
	if (len > 0 && len < sizeof(fd_dir) && access(fd_dir, F_OK) == 0)
	{
		enumerator_t *enumerator = enumerator_create_directory(fd_dir);
		if (enumerator)
		{
			char *rel;
			while (enumerator->enumerate(enumerator, &rel, NULL, NULL))
			{
				fd = atoi(rel);
				if (fd >= lowfd)
				{
					close(fd);
				}
			}
			enumerator->destroy(enumerator);
			return;
		}
	}

	/* ...fall back to closing all fds otherwise */
#ifdef WIN32
	maxfd = _getmaxstdio();
#else
	maxfd = (int)sysconf(_SC_OPEN_MAX);
#endif
	if (maxfd < 0)
	{
		maxfd = 256;
	}
	for (fd = lowfd; fd < maxfd; fd++)
	{
		close(fd);
	}
}
#endif /* HAVE_CLOSEFROM */

/**
 * return null
 */
void *return_null()
{
	return NULL;
}

/**
 * returns TRUE
 */
bool return_true()
{
	return TRUE;
}

/**
 * returns FALSE
 */
bool return_false()
{
	return FALSE;
}

/**
 * nop operation
 */
void nop()
{
}

/**
 * See header
 */
void utils_init()
{
#ifdef WIN32
	windows_init();
#endif
	atomics_init();
	strerror_init();
}

/**
 * See header
 */
void utils_deinit()
{
#ifdef WIN32
	windows_deinit();
#endif
	atomics_deinit();
	strerror_deinit();
}
