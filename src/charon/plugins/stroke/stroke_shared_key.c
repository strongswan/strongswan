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

#include "stroke_shared_key.h"

#include <utils/linked_list.h>

typedef struct private_stroke_shared_key_t private_stroke_shared_key_t;

/**
 * private data of shared_key
 */
struct private_stroke_shared_key_t {

	/**
	 * implements shared_key_t
	 */
	stroke_shared_key_t public;
	
	/**
	 * type of this key
	 */
	shared_key_type_t type;

	/**
	 * data of the key
	 */
	chunk_t key;

	/**
	 * list of key owners, as identification_t
	 */
	linked_list_t *owners;
	
	/**
	 * reference counter
	 */
	refcount_t ref;
};

/**
 * Implementation of shared_key_t.get_type.
 */
static shared_key_type_t get_type(private_stroke_shared_key_t *this)
{
	return this->type;
}

/**
 * Implementation of shared_key_t.get_ref.
 */
static private_stroke_shared_key_t* get_ref(private_stroke_shared_key_t *this)
{
	ref_get(&this->ref);
	return this;
}

/**
 * Implementation of shared_key_t.get_key.
 */
static chunk_t get_key(private_stroke_shared_key_t *this)
{
	return this->key;
}	
	
/**
 * Implementation of stroke_shared_key_t.has_owner.
 */
static id_match_t has_owner(private_stroke_shared_key_t *this, identification_t *owner)
{
	enumerator_t *enumerator;
	id_match_t match, best = ID_MATCH_NONE;
	identification_t *current;
	
	enumerator = this->owners->create_enumerator(this->owners);
	while (enumerator->enumerate(enumerator, &current))
	{
		match  = owner->matches(owner, current);
		if (match > best)
		{
			best = match;
		}
	}
	enumerator->destroy(enumerator);
	return best;
}
/**
 * Implementation of stroke_shared_key_t.add_owner.
 */
static void add_owner(private_stroke_shared_key_t *this, identification_t *owner)
{
	this->owners->insert_last(this->owners, owner);
}

/**
 * Implementation of stroke_shared_key_t.destroy
 */
static void destroy(private_stroke_shared_key_t *this)
{
	if (ref_put(&this->ref))
	{
		this->owners->destroy_offset(this->owners, offsetof(identification_t, destroy));
		chunk_free(&this->key);
		free(this);
	}
}

/**
 * create a shared key
 */
stroke_shared_key_t *stroke_shared_key_create(shared_key_type_t type, chunk_t key)
{
	private_stroke_shared_key_t *this = malloc_thing(private_stroke_shared_key_t);

	this->public.shared.get_type = (shared_key_type_t(*)(shared_key_t*))get_type;
	this->public.shared.get_key = (chunk_t(*)(shared_key_t*))get_key;
	this->public.shared.get_ref = (shared_key_t*(*)(shared_key_t*))get_ref;
	this->public.shared.destroy = (void(*)(shared_key_t*))destroy;
	this->public.add_owner = (void(*)(stroke_shared_key_t*, identification_t *owner))add_owner;
	this->public.has_owner = (id_match_t(*)(stroke_shared_key_t*, identification_t *owner))has_owner;

	this->owners = linked_list_create();
	this->type = type;
	this->key = key;
	this->ref = 1;
	
	return &this->public;
}
