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

#define _GNU_SOURCE /* for memrchr */
#ifdef WIN32
/* for GetTickCount64, Windows 7 */
# define _WIN32_WINNT 0x0601
#endif

#include "utils.h"

#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdint.h>
#include <limits.h>
#include <dirent.h>
#include <time.h>
#ifndef WIN32
# include <signal.h>
#endif

#include <library.h>
#include <utils/debug.h>
#include <utils/chunk.h>
#include <collections/enumerator.h>
#include <threading/mutex.h>
#include <threading/condvar.h>

ENUM(status_names, SUCCESS, NEED_MORE,
	"SUCCESS",
	"FAILED",
	"OUT_OF_RES",
	"ALREADY_DONE",
	"NOT_SUPPORTED",
	"INVALID_ARG",
	"NOT_FOUND",
	"PARSE_ERROR",
	"VERIFY_ERROR",
	"INVALID_STATE",
	"DESTROY_ME",
	"NEED_MORE",
);

/**
 * Described in header.
 */
void* malloc_align(size_t size, u_int8_t align)
{
	u_int8_t pad;
	void *ptr;

	if (align == 0)
	{
		align = 1;
	}
	ptr = malloc(align + sizeof(pad) + size);
	if (!ptr)
	{
		return NULL;
	}
	/* store padding length just before data, down to the allocation boundary
	 * to do some verification during free_align() */
	pad = align - ((uintptr_t)ptr % align);
	memset(ptr, pad, pad);
	return ptr + pad;
}

/**
 * Described in header.
 */
void free_align(void *ptr)
{
	u_int8_t pad, *pos;

	pos = ptr - 1;
	/* verify padding to check any corruption */
	for (pad = *pos; (void*)pos >= ptr - pad; pos--)
	{
		if (*pos != pad)
		{
			DBG1(DBG_LIB, "!!!! invalid free_align() !!!!");
			return;
		}
	}
	free(ptr - pad);
}

#ifdef WIN32

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

/**
 * Described in header.
 */
char* path_dirname(const char *path)
{
	char *pos;

	pos = path ? strrchr(path, DIRECTORY_SEPARATOR[0]) : NULL;

	if (pos && !pos[1])
	{	/* if path ends with slashes we have to look beyond them */
		while (pos > path && *pos == DIRECTORY_SEPARATOR[0])
		{	/* skip trailing slashes */
			pos--;
		}
		pos = memrchr(path, DIRECTORY_SEPARATOR[0], pos - path + 1);
	}
	if (!pos)
	{
#ifdef WIN32
		if (path && strlen(path))
		{
			if ((isalpha(path[0]) && path[1] == ':'))
			{	/* if just a drive letter given, return that as dirname */
				return chunk_clone(chunk_from_chars(path[0], ':', 0)).ptr;
			}
		}
#endif
		return strdup(".");
	}
	while (pos > path && *pos == DIRECTORY_SEPARATOR[0])
	{	/* skip superfluous slashes */
		pos--;
	}
	return strndup(path, pos - path + 1);
}

/**
 * Described in header.
 */
char* path_basename(const char *path)
{
	char *pos, *trail = NULL;

	if (!path || !*path)
	{
		return strdup(".");
	}
	pos = strrchr(path, DIRECTORY_SEPARATOR[0]);
	if (pos && !pos[1])
	{	/* if path ends with slashes we have to look beyond them */
		while (pos > path && *pos == DIRECTORY_SEPARATOR[0])
		{	/* skip trailing slashes */
			pos--;
		}
		if (pos == path && *pos == DIRECTORY_SEPARATOR[0])
		{	/* contains only slashes */
			return strdup(DIRECTORY_SEPARATOR);
		}
		trail = pos + 1;
		pos = memrchr(path, DIRECTORY_SEPARATOR[0], trail - path);
	}
	pos = pos ? pos + 1 : (char*)path;
	return trail ? strndup(pos, trail - pos) : strdup(pos);
}

/**
 * Described in header.
 */
bool path_absolute(const char *path)
{
	if (!path)
	{
		return FALSE;
	}
#ifdef WIN32
	if (strpfx(path, "\\\\"))
	{	/* UNC */
		return TRUE;
	}
	if (strlen(path) && isalpha(path[0]) && path[1] == ':')
	{	/* drive letter */
		return TRUE;
	}
#else /* !WIN32 */
	if (path[0] == DIRECTORY_SEPARATOR[0])
	{
		return TRUE;
	}
#endif
	return FALSE;
}

/**
 * Described in header.
 */
bool mkdir_p(const char *path, mode_t mode)
{
	int len;
	char *pos, full[PATH_MAX];
	pos = full;
	if (!path || *path == '\0')
	{
		return TRUE;
	}
	len = snprintf(full, sizeof(full)-1, "%s", path);
	if (len < 0 || len >= sizeof(full)-1)
	{
		DBG1(DBG_LIB, "path string %s too long", path);
		return FALSE;
	}
	/* ensure that the path ends with a '/' */
	if (full[len-1] != '/')
	{
		full[len++] = '/';
		full[len] = '\0';
	}
	/* skip '/' at the beginning */
	while (*pos == '/')
	{
		pos++;
	}
	while ((pos = strchr(pos, '/')))
	{
		*pos = '\0';
		if (access(full, F_OK) < 0)
		{
#ifdef WIN32
			if (_mkdir(full) < 0)
#else
			if (mkdir(full, mode) < 0)
#endif
			{
				DBG1(DBG_LIB, "failed to create directory %s", full);
				return FALSE;
			}
		}
		*pos = '/';
		pos++;
	}
	return TRUE;
}

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
 * Return monotonic time
 */
time_t time_monotonic(timeval_t *tv)
{
#ifdef WIN32
	ULONGLONG ms;
	time_t s;

	ms = GetTickCount64();
	s = ms / 1000;
	if (tv)
	{
		tv->tv_sec = s;
		tv->tv_usec = (ms - (s * 1000)) * 1000;
	}
	return s;
#else /* !WIN32 */
#if defined(HAVE_CLOCK_GETTIME) && \
	(defined(HAVE_CONDATTR_CLOCK_MONOTONIC) || \
	 defined(HAVE_PTHREAD_COND_TIMEDWAIT_MONOTONIC))
	/* as we use time_monotonic() for condvar operations, we use the
	 * monotonic time source only if it is also supported by pthread. */
	timespec_t ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
	{
		if (tv)
		{
			tv->tv_sec = ts.tv_sec;
			tv->tv_usec = ts.tv_nsec / 1000;
		}
		return ts.tv_sec;
	}
#endif /* HAVE_CLOCK_GETTIME && (...) */
	/* Fallback to non-monotonic timestamps:
	 * On MAC OS X, creating monotonic timestamps is rather difficult. We
	 * could use mach_absolute_time() and catch sleep/wakeup notifications.
	 * We stick to the simpler (non-monotonic) gettimeofday() for now.
	 * But keep in mind: we need the same time source here as in condvar! */
	if (!tv)
	{
		return time(NULL);
	}
	if (gettimeofday(tv, NULL) != 0)
	{	/* should actually never fail if passed pointers are valid */
		return -1;
	}
	return tv->tv_sec;
#endif /* !WIN32 */
}

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
 * returns FAILED
 */
status_t return_failed()
{
	return FAILED;
}

/**
 * returns SUCCESS
 */
status_t return_success()
{
	return SUCCESS;
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

/**
 * Described in header.
 */
int time_printf_hook(printf_hook_data_t *data, printf_hook_spec_t *spec,
					 const void *const *args)
{
	static const char* months[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	time_t *time = *((time_t**)(args[0]));
	bool utc = *((int*)(args[1]));
	struct tm t, *ret = NULL;

	if (*time != UNDEFINED_TIME)
	{
		if (utc)
		{
			ret = gmtime_r(time, &t);
		}
		else
		{
			ret = localtime_r(time, &t);
		}
	}
	if (ret == NULL)
	{
		return print_in_hook(data, "--- -- --:--:--%s----",
							 utc ? " UTC " : " ");
	}
	return print_in_hook(data, "%s %02d %02d:%02d:%02d%s%04d",
						 months[t.tm_mon], t.tm_mday, t.tm_hour, t.tm_min,
						 t.tm_sec, utc ? " UTC " : " ", t.tm_year + 1900);
}

/**
 * Described in header.
 */
int time_delta_printf_hook(printf_hook_data_t *data, printf_hook_spec_t *spec,
						   const void *const *args)
{
	char* unit = "second";
	time_t *arg1 = *((time_t**)(args[0]));
	time_t *arg2 = *((time_t**)(args[1]));
	u_int64_t delta = llabs(*arg1 - *arg2);

	if (delta > 2 * 60 * 60 * 24)
	{
		delta /= 60 * 60 * 24;
		unit = "day";
	}
	else if (delta > 2 * 60 * 60)
	{
		delta /= 60 * 60;
		unit = "hour";
	}
	else if (delta > 2 * 60)
	{
		delta /= 60;
		unit = "minute";
	}
	return print_in_hook(data, "%" PRIu64 " %s%s", delta, unit,
						 (delta == 1) ? "" : "s");
}
