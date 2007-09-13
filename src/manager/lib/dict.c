/**
 * @file dict.c
 *
 * @brief Implementation of dict_t.
 *
 */

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

#include "dict.h"

#include <utils/linked_list.h>


typedef struct private_dict_t private_dict_t;

/**
 * private data of dict
 */
struct private_dict_t {

	/**
	 * public functions
	 */
	dict_t public;
	
	/**
	 * baaah, we really should have a hashtable for this
	 */
	linked_list_t *list;
	
	/**
	 * key comparator function
	 */
	bool(*key_comparator)(void*,void*);
	
	/**
	 * destructor function for key
	 */
	 void(*key_destructor)(void*);
	 
	 /**
	  * destructor function for value
	  */
	 void(*value_destructor)(void*);
};

/**
 * key value pair to store entries
 */
typedef struct {
	void *key;
	void *value;
} key_value_t;

/**
 * Implementation of dict_t.get.
 */
static void* get(private_dict_t *this, void *key)
{
	key_value_t *kv;
	iterator_t *iterator;
	void *value = NULL;
	
	iterator = this->list->create_iterator(this->list, TRUE);
	while (iterator->iterate(iterator, (void**)&kv))
	{
		if (this->key_comparator(kv->key, key))
		{
			value = kv->value;
			break;
		}
	}
	iterator->destroy(iterator);
	return value;
}
/**
 * Implementation of dict_t.set.
 */
static void set(private_dict_t *this, void *key, void *value)
{
	/* we don't overwrite, just prepend */
	key_value_t *kv = malloc_thing(key_value_t);
	kv->key = key;
	kv->value = value;
	this->list->insert_first(this->list, kv);
}


/**
 * comparator for strings
 */
bool dict_streq(void *a, void *b)
{
	return streq(a, b);
}

/**
 * Implementation of dict_t.destroy
 */
static void destroy(private_dict_t *this)
{
	key_value_t *kv;

	while (this->list->remove_last(this->list, (void**)&kv) == SUCCESS)
	{
		if (this->key_destructor)
		{
			this->key_destructor(kv->key);
		}
		if (this->value_destructor)
		{
			this->value_destructor(kv->value);
		}
		free(kv);
	}
	this->list->destroy(this->list);
	free(this);
}

/*
 * see header file
 */
dict_t *dict_create(bool(*key_comparator)(void*,void*),
					void(*key_destructor)(void*),
					void(*value_destructor)(void*))
{
	private_dict_t *this = malloc_thing(private_dict_t);
	
	this->public.set = (void(*)(dict_t*, void *key, void *value))set;
	this->public.get = (void*(*)(dict_t*, void *key))get;
	this->public.destroy = (void(*)(dict_t*))destroy;
	
	this->list = linked_list_create();
	this->key_comparator = key_comparator;
	this->key_destructor = key_destructor;
	this->value_destructor = value_destructor;
	
	return &this->public;
}

