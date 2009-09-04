/*
 * Copyright (C) 2007 Martin Willi
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

#include "shared_key.h"

ENUM(shared_key_type_names, SHARED_ANY, SHARED_PIN,
	"ANY",
	"IKE",
	"EAP",
	"PRIVATE_KEY_PASS",
	"PIN",
);

typedef struct private_shared_key_t private_shared_key_t;

/**
 * private data of shared_key
 */
struct private_shared_key_t {

	/**
	 * public functions
	 */
	shared_key_t public;

	/**
	 * type of this shared key
	 */
	shared_key_type_t type;

	/**
	 * associated shared key data
	 */
	chunk_t key;

	/**
	 * reference counter
	 */
	refcount_t ref;
};

/**
 * Implements shared_key_t.get_type
 */
static shared_key_type_t get_type(private_shared_key_t *this)
{
	return this->type;
}

/**
 * Implements shared_key_t.get_key
 */
static chunk_t get_key(private_shared_key_t *this)
{
	return this->key;
}

/**
 * Implements shared_key_t.get_ref
 */
static shared_key_t* get_ref(private_shared_key_t *this)
{
	ref_get(&this->ref);
	return &this->public;
}

/**
 * Implementation of shared_key_t.destroy
 */
static void destroy(private_shared_key_t *this)
{
	if (ref_put(&this->ref))
	{
		free(this->key.ptr);
		free(this);
	}
}

/*
 * see header file
 */
shared_key_t *shared_key_create(shared_key_type_t type, chunk_t key)
{
	private_shared_key_t *this = malloc_thing(private_shared_key_t);

	this->public.get_type = (shared_key_type_t (*)(shared_key_t *this))get_type;
	this->public.get_key = (chunk_t (*)(shared_key_t *this))get_key;
	this->public.get_ref = (shared_key_t* (*)(shared_key_t *this))get_ref;
	this->public.destroy = (void(*)(shared_key_t*))destroy;

	this->type = type;
	this->key = key;
	this->ref = 1;

	return &this->public;
}

