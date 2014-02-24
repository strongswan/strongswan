/*
 * Copyright (C) 2012-2014 Tobias Brunner
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

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "strerror.h"

/**
 * The size of the thread-specific error buffer
 */
#define STRERROR_BUF_LEN 256

/**
 * Key to store thread-specific error buffer
 */
static pthread_key_t strerror_buf_key;

/**
 * Only initialize the key above once
 */
static pthread_once_t strerror_buf_key_once = PTHREAD_ONCE_INIT;

/**
 * Create the key used for the thread-specific error buffer
 */
static void create_strerror_buf_key()
{
	pthread_key_create(&strerror_buf_key, free);
}

/**
 * Retrieve the error buffer assigned to the current thread (or create it)
 */
static inline char *get_strerror_buf()
{
	char *buf;

	pthread_once(&strerror_buf_key_once, create_strerror_buf_key);
	buf = pthread_getspecific(strerror_buf_key);
	if (!buf)
	{
		buf = malloc(STRERROR_BUF_LEN);
		pthread_setspecific(strerror_buf_key, buf);
	}
	return buf;
}

#ifdef HAVE_STRERROR_R
/*
 * Described in header.
 */
const char *strerror_safe(int errnum)
{
	char *buf = get_strerror_buf(), *msg;

#ifdef STRERROR_R_CHAR_P
	/* char* version which may or may not return the original buffer */
	msg = strerror_r(errnum, buf, STRERROR_BUF_LEN);
#else
	/* int version returns 0 on success */
	msg = strerror_r(errnum, buf, STRERROR_BUF_LEN) ? "Unknown error" : buf;
#endif
	return msg;
}
#else /* HAVE_STRERROR_R */
/* we actually wan't to call strerror(3) below */
#undef strerror
/*
 * Described in header.
 */
const char *strerror_safe(int errnum)
{
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	char *buf = get_strerror_buf();

	/* use a mutex to ensure calling strerror(3) is thread-safe */
	pthread_mutex_lock(&mutex);
	strncpy(buf, strerror(errnum), STRERROR_BUF_LEN);
	pthread_mutex_unlock(&mutex);
	buf[STRERROR_BUF_LEN - 1] = '\0';
	return buf;
}
#endif /* HAVE_STRERROR_R */
