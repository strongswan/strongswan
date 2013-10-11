/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

/**
 * @defgroup windows windows
 * @{ @ingroup utils
 */

#ifndef WINDOWS_H_
#define WINDOWS_H_

#include <winsock2.h>
#include <ws2tcpip.h>
#include <direct.h>

/* undef Windows variants evaluating values more than once */
#undef min
#undef max

/* interface is defined as an alias to "struct" in basetypes.h, but
 * we use it here and there as ordinary identifier. */
#undef interface

/* used by Windows API, but we have our own */
#undef CALLBACK

/* UID/GID types for capabilities, even if not supported */
typedef u_int uid_t;
typedef u_int gid_t;

/**
 * Replacement for random(3)
 */
static inline long random(void)
{
	return rand();
}

/**
 * Replacement for srandom(3)
 */
static inline void srandom(unsigned int seed)
{
	srand(seed);
}

/**
 * Provided via ws2_32
 */
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

/**
 * Provided via ws2_32
 */
int inet_pton(int af, const char *src, void *dst);

/**
 * Provided by printf hook backend
 */
int asprintf(char **strp, const char *fmt, ...);

/**
 * Provided by printf hook backend
 */
int vasprintf(char **strp, const char *fmt, va_list ap);

/**
 * timeradd(3) from <sys/time.h>
 */
static inline void timeradd(struct timeval *a, struct timeval *b,
							struct timeval *res)
{
	res->tv_sec = a->tv_sec + b->tv_sec;
	res->tv_usec = a->tv_usec + b->tv_usec;
	if (res->tv_usec >= 1000000)
	{
		res->tv_usec -= 1000000;
		res->tv_sec++;
	}
}

/**
 * timersub(3) from <sys/time.h>
 */
static inline void timersub(struct timeval *a, struct timeval *b,
							struct timeval *res)
{
	res->tv_sec = a->tv_sec - b->tv_sec;
	res->tv_usec = a->tv_usec - b->tv_usec;
	if (res->tv_usec < 0)
	{
		res->tv_usec += 1000000;
		res->tv_sec--;
	}
}

/**
 * gmtime_r(3) from <time.h>
 */
static inline struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
	if (sizeof(time_t) == 4)
	{
		if (_gmtime32_s(result, (__time32_t*)time) == 0)
		{
			return result;
		}
	}
	else
	{
		if (_gmtime64_s(result, (__time64_t*)time) == 0)
		{
			return result;
		}
	}
	return NULL;
}

/**
 * localtime_r(3) from <time.h>
 */
static inline struct tm *localtime_r(const time_t *timep, struct tm *result)
{
	if (sizeof(time_t) == 4)
	{
		if (_localtime32_s(result, (__time32_t*)time) == 0)
		{
			return result;
		}
	}
	else
	{
		if (_localtime64_s(result, (__time64_t*)time) == 0)
		{
			return result;
		}
	}
	return NULL;
}

#endif /** WINDOWS_H_ @}*/
