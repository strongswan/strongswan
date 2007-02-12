/**
 * @file library.c
 *
 * @brief Helper functions and definitions.
 *
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>

#include "library.h"

#include <printf_hook.h>

ENUM(status_names, SUCCESS, DESTROY_ME,
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
void *clalloc(void * pointer, size_t size)
{
	void *data;
	data = malloc(size);
	
	memcpy(data, pointer,size);
	
	return (data);
}

/**
 * Described in header.
 */
void memxor(u_int8_t dest[], u_int8_t src[], size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
	{
		dest[i] ^= src[i];
	}
}

/**
 * We use a single mutex for all refcount variables. This
 * is not optimal for performance, but the critical section
 * is not that long...
 * TODO: Consider to include a mutex in each refcount_t variable.
 */
static pthread_mutex_t ref_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Described in header.
 * 
 * TODO: May be implemented with atomic CPU instructions
 * instead of a mutex.
 */
void ref_get(refcount_t *ref)
{
	pthread_mutex_lock(&ref_mutex);
	(*ref)++;
	pthread_mutex_unlock(&ref_mutex);
}

/**
 * Described in header.
 * 
 * TODO: May be implemented with atomic CPU instructions
 * instead of a mutex.
 */
bool ref_put(refcount_t *ref)
{
	bool more_refs;
	
	pthread_mutex_lock(&ref_mutex);
	more_refs = --(*ref);
	pthread_mutex_unlock(&ref_mutex);
	return !more_refs;
}

/**
 * output handler in printf() for time_t
 */
static int print_time(FILE *stream, const struct printf_info *info,
					  const void *const *args)
{
	static const char* months[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	time_t *time = *((time_t**)(args[0]));
	bool utc = TRUE;
	struct tm t;
	
	if (info->alt)
	{
		utc = *((bool*)(args[1]));
	}
	if (time == UNDEFINED_TIME)
	{
		return fprintf(stream, "--- -- --:--:--%s----",
					   info->alt ? " UTC " : " ");
	}
	if (utc)
	{
		gmtime_r(time, &t);
	}
	else
	{
		localtime_r(time, &t);
	}
	return fprintf(stream, "%s %02d %02d:%02d:%02d%s%04d",
				   months[t.tm_mon], t.tm_mday, t.tm_hour, t.tm_min,
				   t.tm_sec, utc ? " UTC " : " ", t.tm_year + 1900);
}

/**
 * output handler in printf() for time deltas
 */
static int print_time_delta(FILE *stream, const struct printf_info *info,
							const void *const *args)
{
	time_t *start = *((time_t**)(args[0]));
	time_t *end   = *((time_t**)(args[1]));
	u_int delta   = abs(*end - *start);

	char* unit = "second";

	if (delta > 2 * 60 * 60 * 24)
	{
		delta /= 60 * 60 * 24;
		unit = "days";
	}
	else if (delta > 2 * 60 * 60)
	{
		delta /= 60 * 60;
		unit = "hours";
	}
	else if (delta > 2 * 60)
	{
		delta /= 60;
		unit = "minutes";
	}
	return fprintf(stream, "%d %s", delta, unit);
}

/**
 * register printf() handlers for time_t
 */
static void __attribute__ ((constructor))print_register()
{
	register_printf_function(PRINTF_TIME, print_time, arginfo_ptr_alt_ptr_int);
	register_printf_function(PRINTF_TIME_DELTA, print_time_delta, arginfo_ptr_ptr);
}
