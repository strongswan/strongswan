/*
 * Copyright (C) 2008 Tobias Brunner
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
 *
 * $Id$
 */

#include <utils/linked_list.h>

#include "hashtable.h"

/** The maximum capacity of the hash table (MUST be a power of 2) */
#define MAX_CAPACITY (1 << 30)

typedef struct pair_t pair_t;

/**
 * This pair holds a pointer to the key and value it represents.
 */
struct pair_t {
	/**
	 * Key of a hash table item.
	 */
	void *key;
	
	/**
	 * Value of a hash table item.
	 */
	void *value;
	
	/**
	 * Cached hash (used in case of a resize).
	 */
	u_int hash;
};

/**
 * Creates an empty pair object.
 */
pair_t *pair_create(void *key, void *value, u_int hash)
{
	pair_t *this = malloc_thing(pair_t);
	
	this->key = key;
	this->value = value;
	this->hash = hash;
	
	return this;
}

typedef struct private_hashtable_t private_hashtable_t;

/**
 * Private data of a hashtable_t object.
 *
 */
struct private_hashtable_t {
	/**
	 * Public part of hash table.
	 */
	hashtable_t public;
	
	/**
	 * The number of items in the hash table. 
	 */
	u_int count;
	
	/**
	 * The current capacity of the hash table (always a power of 2).
	 */
	u_int capacity;
	
	/**
	 * The current mask to calculate the row index (capacity - 1). 
	 */
	u_int mask;
	
	/**
	 * The load factor.
	 */
	float load_factor;
	
	/**
	 * The actual table.
	 */
	linked_list_t **table;
	
	/**
	 * The hashing function.
	 */
	hashtable_hash_t hash;
	
	/**
	 * The equality function.
	 */
	hashtable_equals_t equals;
};

typedef struct private_enumerator_t private_enumerator_t;

/**
 * hash table enumerator implementation
 */
struct private_enumerator_t {

	/**
	 * implements enumerator interface
	 */
	enumerator_t enumerator;
	
	/**
	 * associated hash table
	 */
	private_hashtable_t *table;
	
	/**
	 * current row index
	 */
	u_int row;
	
	/**
	 * enumerator for the current row
	 */
	enumerator_t *current;
};

/**
 * Compare a pair in a list with the given key.
 */
static inline bool pair_equals(pair_t *pair, private_hashtable_t *this, void *key)
{
	return this->equals(key, pair->key);
}

/**
 * This function returns the next-highest power of two for the given number.
 * The algorithm works by setting all bits on the right-hand side of the most
 * significant 1 to 1 and then increments the whole number so it rolls over
 * to the nearest power of two. Note: returns 0 for n == 0
 */
static u_int get_nearest_powerof2(u_int n)
{
	u_int i;
	--n;
	for (i = 1; i < sizeof(u_int) * 8; i <<= 1)
	{
		n |= n >> i;
	}
	return ++n;
}

/**
 * Init hash table parameters
 */
static void init_hashtable(private_hashtable_t *this, u_int capacity)
{
	capacity = max(1, min(capacity, MAX_CAPACITY));
	this->capacity = get_nearest_powerof2(capacity);
	this->mask = this->capacity - 1;
	this->load_factor = 0.75;
	
	this->table = calloc(this->capacity, sizeof(linked_list_t*));
}

/**
 * Double the size of the hash table and rehash all the elements.
 */
static void rehash(private_hashtable_t *this)
{
	u_int row;
	u_int old_capacity = this->capacity;
	linked_list_t **old_table = this->table;
	
	if (old_capacity >= MAX_CAPACITY)
	{
		return;
	}
	
	init_hashtable(this, old_capacity << 1);
	
	for (row = 0; row < old_capacity; ++row)
	{
		linked_list_t *list;
		if ((list = old_table[row]) != NULL)
		{
			pair_t *pair;
			enumerator_t *enumerator = list->create_enumerator(list);
			while (enumerator->enumerate(enumerator, &pair))
			{
				linked_list_t *new_list;
				u_int new_row = pair->hash & this->mask;
				list->remove_at(list, enumerator);
				if ((new_list = this->table[new_row]) == NULL)
				{
					new_list = this->table[new_row] = linked_list_create();
				}
				new_list->insert_last(new_list, pair);
			}
			enumerator->destroy(enumerator);
			list->destroy(list);
		}
	}
	free(old_table);
}

/**
 * Implementation of hashtable_t.put
 */
static void *put(private_hashtable_t *this, void *key, void *value)
{
	linked_list_t *list;
	void *old_value = NULL;
	u_int hash = this->hash(key);
	u_int row = hash & this->mask;
	
	if ((list = this->table[row]) != NULL)
	{
		pair_t *pair;
		enumerator_t *enumerator = list->create_enumerator(list);
		while (enumerator->enumerate(enumerator, &pair))
		{
			if (pair_equals(pair, this, key))
			{
				old_value = pair->value;
				pair->value = value;
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	else
	{
		list = this->table[row] = linked_list_create();
	}
	
	if (!old_value)
	{
		list->insert_last(list, pair_create(key, value, hash));
		this->count++;
	}
	
	if (this->count >= this->capacity * this->load_factor)
	{
		rehash(this);
	}
	
	return old_value;
}
	
/**
 * Implementation of hashtable_t.get  
 */
static void *get(private_hashtable_t *this, void *key)
{
	void *value = NULL;
	linked_list_t *list;
	u_int row = this->hash(key) & this->mask;
	
	if ((list = this->table[row]) != NULL)
	{
		pair_t *pair;
		if (list->find_first(list, (linked_list_match_t)pair_equals,
				(void**)&pair, this, key) == SUCCESS)
		{
			value = pair->value;
		}
	}
	
	return value;
}
	
/**
 * Implementation of hashtable_t.remove
 */
static void *remove(private_hashtable_t *this, void *key)
{
	void *value = NULL;
	linked_list_t *list;
	u_int row = this->hash(key) & this->mask;	
	
	if ((list = this->table[row]) != NULL)
	{
		pair_t *pair;
		enumerator_t *enumerator = list->create_enumerator(list);
		while (enumerator->enumerate(enumerator, &pair))
		{
			if (pair_equals(pair, this, key))
			{
				list->remove_at(list, enumerator);
				value = pair->value;
				this->count--;
				free(pair);
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	
	return value;
}
	
/**
 * Implementation of hashtable_t.get_count
 */
static u_int get_count(private_hashtable_t *this)
{
	return this->count;
}

/**
 * Implementation of private_enumerator_t.enumerator.enumerate.
 */
static bool enumerate(private_enumerator_t *this, void **key, void **value)
{
	while (this->row < this->table->capacity)
	{
		if (this->current)
		{
			pair_t *pair;
			
			if (this->current->enumerate(this->current, &pair))
			{
				if (key)
				{
					*key = pair->key;
				}
				if (value)
				{
					*value = pair->value;
				}
				return TRUE;
			}
			this->current->destroy(this->current);
			this->current = NULL;
		}
		else
		{
			linked_list_t *list;
			
			if ((list = this->table->table[this->row]) != NULL)
			{
				this->current = list->create_enumerator(list);
				continue;
			}
		}
		this->row++;
	}
	return FALSE;
}

/**
 * Implementation of private_enumerator_t.enumerator.destroy.
 */
static void enumerator_destroy(private_enumerator_t *this)
{
	if (this->current)
	{
		this->current->destroy(this->current);
	}
	free(this);
}

/**
 * Implementation of hashtable_t.create_enumerator.
 */
static enumerator_t* create_enumerator(private_hashtable_t *this)
{
	private_enumerator_t *enumerator = malloc_thing(private_enumerator_t);
	
	enumerator->enumerator.enumerate = (void*)enumerate;
	enumerator->enumerator.destroy = (void*)enumerator_destroy;
	enumerator->table = this;
	enumerator->row = 0;
	enumerator->current = NULL;
	
	return &enumerator->enumerator;
}
	
/**
 * Implementation of hashtable_t.destroy
 */
static void destroy(private_hashtable_t *this)
{
	u_int row;
	for (row = 0; row < this->capacity; ++row)
	{
		linked_list_t *list;
		if ((list = this->table[row]) != NULL)
		{
			list->destroy_function(list, free);
		}
	}
	free(this->table);
	free(this);
}

/*
 * Described in header.
 */
hashtable_t *hashtable_create(hashtable_hash_t hash, hashtable_equals_t equals,
							  u_int capacity)
{
	private_hashtable_t *this = malloc_thing(private_hashtable_t);

	this->public.put = (void*(*)(hashtable_t*,void*,void*))put;
	this->public.get = (void*(*)(hashtable_t*,void*))get; 
	this->public.remove = (void*(*)(hashtable_t*,void*))remove;
	this->public.get_count = (u_int(*)(hashtable_t*))get_count;
	this->public.create_enumerator = (enumerator_t*(*)(hashtable_t*))create_enumerator;
	this->public.destroy = (void(*)(hashtable_t*))destroy;
	
	this->count = 0;
	this->capacity = 0;
	this->mask = 0;
	this->load_factor = 0;
	this->table = NULL;
	this->hash = hash;
	this->equals = equals;
	
	init_hashtable(this, capacity);
	
	return &this->public;
}
