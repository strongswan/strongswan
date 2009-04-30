/*
 * Copyright (C) 2008 Martin Willi
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

#include "user.h"

typedef struct private_user_t private_user_t;

/**
 * private data of user
 */
struct private_user_t {

	/**
	 * public functions
	 */
	user_t public;

	/**
	 * user id, if we are logged in; otherwise 0
	 */
	u_int user;
};

/**
 * Implementation of user_t.set_user
 */
static void set_user(private_user_t *this, u_int id)
{
	this->user = id;
}

/**
 * Implementation of user_t.get_user
 */
static u_int get_user(private_user_t *this)
{
	return this->user;
}

/**
 * Implementation of context_t.destroy
 */
static void destroy(private_user_t *this)
{
	free(this);
}

/*
 * see header file
 */
user_t *user_create(void *param)
{
	private_user_t *this= malloc_thing(private_user_t);

	this->public.set_user = (void(*)(user_t*,u_int id))set_user;
	this->public.get_user = (u_int(*)(user_t*))get_user;
	this->public.context.destroy = (void(*)(context_t*))destroy;

	this->user = 0;

	return &this->public;
}

