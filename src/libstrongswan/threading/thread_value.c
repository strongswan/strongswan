/*
 * Copyright (C) 2009 Tobias Brunner
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

#define _GNU_SOURCE
#include <pthread.h>

#include <library.h>

#include "thread_value.h"

typedef struct private_thread_value_t private_thread_value_t;

struct private_thread_value_t {
	/**
	 * Public interface.
	 */
	thread_value_t public;

	/**
	 * Key to access thread-specific values.
	 */
	pthread_key_t key;

};


/**
 * Implementation of thread_value_t.set.
 */
static void set(private_thread_value_t *this, void *val)
{
	pthread_setspecific(this->key, val);
}

/**
 * Implementation of thread_value_t.get.
 */
static void *get(private_thread_value_t *this)
{
	return pthread_getspecific(this->key);
}

/**
 * Implementation of thread_value_t.destroy.
 */
static void destroy(private_thread_value_t *this)
{
	pthread_key_delete(this->key);
	free(this);
}


/**
 * Described in header.
 */
thread_value_t *thread_value_create(thread_cleanup_t destructor)
{
	private_thread_value_t *this = malloc_thing(private_thread_value_t);
	this->public.set = (void(*)(thread_value_t*,void*))set;
	this->public.get = (void*(*)(thread_value_t*))get;
	this->public.destroy = (void(*)(thread_value_t*))destroy;

	pthread_key_create(&this->key, destructor);
	return &this->public;
}

