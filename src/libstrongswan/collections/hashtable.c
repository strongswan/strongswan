/*
 * Copyright (C) 2008-2020 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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

#include "hashtable.h"

#include <utils/chunk.h>

/** The minimum capacity of the hash table (MUST be a power of 2) */
#define MIN_CAPACITY 8
/** The maximum capacity of the hash table (MUST be a power of 2) */
#define MAX_CAPACITY (1 << 30)
/** Maximum load factor before the hash table is resized */
#define LOAD_FACTOR 0.75f

typedef struct pair_t pair_t;

/**
 * This pair holds a pointer to the key and value it represents.
 */
struct pair_t {

	/**
	 * Key of a hash table item.
	 */
	const void *key;

	/**
	 * Value of a hash table item.
	 */
	void *value;

	/**
	 * Cached hash (used in case of a resize).
	 */
	u_int hash;

	/**
	 * Next pair in an overflow list.
	 */
	pair_t *next;
};

/**
 * Creates an empty pair object.
 */
static inline pair_t *pair_create(const void *key, void *value, u_int hash)
{
	pair_t *this;

	INIT(this,
		.key = key,
		.value = value,
		.hash = hash,
	);

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
	 * The actual table.
	 */
	pair_t **table;

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
	 * number of remaining items in hashtable
	 */
	u_int count;

	/**
	 * current pair
	 */
	pair_t *current;

	/**
	 * previous pair (used by remove_at)
	 */
	pair_t *prev;
};

/*
 * See header.
 */
u_int hashtable_hash_ptr(const void *key)
{
	return chunk_hash(chunk_from_thing(key));
}

/*
 * See header.
 */
u_int hashtable_hash_str(const void *key)
{
	return chunk_hash(chunk_from_str((char*)key));
}

/*
 * See header.
 */
bool hashtable_equals_ptr(const void *key, const void *other_key)
{
	return key == other_key;
}

/*
 * See header.
 */
bool hashtable_equals_str(const void *key, const void *other_key)
{
	return streq(key, other_key);
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
	capacity = max(MIN_CAPACITY, min(capacity, MAX_CAPACITY));
	this->capacity = get_nearest_powerof2(capacity);
	this->mask = this->capacity - 1;

	this->table = calloc(this->capacity, sizeof(pair_t*));
}

/**
 * Double the size of the hash table and rehash all the elements.
 */
static void rehash(private_hashtable_t *this)
{
	pair_t **old_table, *to_move, *pair, *next;
	u_int row, new_row, old_capacity;

	if (this->capacity >= MAX_CAPACITY)
	{
		return;
	}

	old_capacity = this->capacity;
	old_table = this->table;

	init_hashtable(this, old_capacity << 1);

	for (row = 0; row < old_capacity; row++)
	{
		to_move = old_table[row];
		while (to_move)
		{
			new_row = to_move->hash & this->mask;
			pair = this->table[new_row];
			if (pair)
			{
				while (pair->next)
				{
					pair = pair->next;
				}
				pair->next = to_move;
			}
			else
			{
				this->table[new_row] = to_move;
			}
			next = to_move->next;
			to_move->next = NULL;
			to_move = next;
		}
	}
	free(old_table);
}

/**
 * Find the pair with the given key, optionally returning the hash and previous
 * (or last) pair in the bucket.
 */
static inline pair_t *find_key(private_hashtable_t *this, const void *key,
							   hashtable_equals_t equals, u_int *out_hash,
							   pair_t **out_prev)
{
	pair_t *pair, *prev = NULL;
	u_int hash;

	if (!this->count && !out_hash)
	{	/* no need to calculate the hash if not requested */
		return NULL;
	}

	hash = this->hash(key);
	if (out_hash)
	{
		*out_hash = hash;
	}

	pair = this->table[hash & this->mask];
	while (pair)
	{
		if (hash == pair->hash && equals(key, pair->key))
		{
			break;
		}
		prev = pair;
		pair = pair->next;
	}
	if (out_prev)
	{
		*out_prev = prev;
	}
	return pair;
}

METHOD(hashtable_t, put, void*,
	private_hashtable_t *this, const void *key, void *value)
{
	void *old_value = NULL;
	pair_t *pair, *prev = NULL;
	u_int hash;

	if (this->count >= this->capacity * LOAD_FACTOR)
	{
		rehash(this);
	}

	pair = find_key(this, key, this->equals, &hash, &prev);
	if (pair)
	{
		old_value = pair->value;
		pair->value = value;
		pair->key = key;
	}
	else
	{
		pair = pair_create(key, value, hash);
		if (prev)
		{
			prev->next = pair;
		}
		else
		{
			this->table[hash & this->mask] = pair;

		}
		this->count++;
	}
	return old_value;
}


METHOD(hashtable_t, get, void*,
	private_hashtable_t *this, const void *key)
{
	pair_t *pair = find_key(this, key, this->equals, NULL, NULL);
	return pair ? pair->value : NULL;
}

METHOD(hashtable_t, get_match, void*,
	private_hashtable_t *this, const void *key, hashtable_equals_t match)
{
	pair_t *pair = find_key(this, key, match, NULL, NULL);
	return pair ? pair->value : NULL;
}

METHOD(hashtable_t, remove_, void*,
	private_hashtable_t *this, const void *key)
{
	void *value = NULL;
	pair_t *pair, *prev = NULL;

	pair = find_key(this, key, this->equals, NULL, &prev);
	if (pair)
	{
		if (prev)
		{
			prev->next = pair->next;
		}
		else
		{
			this->table[pair->hash & this->mask] = pair->next;
		}
		value = pair->value;
		free(pair);
		this->count--;
	}
	return value;
}

METHOD(hashtable_t, remove_at, void,
	private_hashtable_t *this, private_enumerator_t *enumerator)
{
	if (enumerator->table == this && enumerator->current)
	{
		pair_t *current = enumerator->current;
		if (enumerator->prev)
		{
			enumerator->prev->next = current->next;
		}
		else
		{
			this->table[enumerator->row] = current->next;
		}
		enumerator->current = enumerator->prev;
		free(current);
		this->count--;
	}
}

METHOD(hashtable_t, get_count, u_int,
	private_hashtable_t *this)
{
	return this->count;
}

METHOD(enumerator_t, enumerate, bool,
	private_enumerator_t *this, va_list args)
{
	const void **key;
	void **value;

	VA_ARGS_VGET(args, key, value);

	while (this->count && this->row < this->table->capacity)
	{
		this->prev = this->current;
		if (this->current)
		{
			this->current = this->current->next;
		}
		else
		{
			this->current = this->table->table[this->row];
		}
		if (this->current)
		{
			if (key)
			{
				*key = this->current->key;
			}
			if (value)
			{
				*value = this->current->value;
			}
			this->count--;
			return TRUE;
		}
		this->row++;
	}
	return FALSE;
}

METHOD(hashtable_t, create_enumerator, enumerator_t*,
	private_hashtable_t *this)
{
	private_enumerator_t *enumerator;

	INIT(enumerator,
		.enumerator = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _enumerate,
			.destroy = (void*)free,
		},
		.table = this,
		.count = this->count,
	);

	return &enumerator->enumerator;
}

static void destroy_internal(private_hashtable_t *this,
							 void (*fn)(void*,const void*))
{
	pair_t *pair, *next;
	u_int row;

	for (row = 0; row < this->capacity; row++)
	{
		pair = this->table[row];
		while (pair)
		{
			if (fn)
			{
				fn(pair->value, pair->key);
			}
			next = pair->next;
			free(pair);
			pair = next;
		}
	}
	free(this->table);
	free(this);
}

METHOD(hashtable_t, destroy, void,
	private_hashtable_t *this)
{
	destroy_internal(this, NULL);
}

METHOD(hashtable_t, destroy_function, void,
	private_hashtable_t *this, void (*fn)(void*,const void*))
{
	destroy_internal(this, fn);
}

/*
 * Described in header.
 */
hashtable_t *hashtable_create(hashtable_hash_t hash, hashtable_equals_t equals,
							  u_int capacity)
{
	private_hashtable_t *this;

	INIT(this,
		.public = {
			.put = _put,
			.get = _get,
			.get_match = _get_match,
			.remove = _remove_,
			.remove_at = (void*)_remove_at,
			.get_count = _get_count,
			.create_enumerator = _create_enumerator,
			.destroy = _destroy,
			.destroy_function = _destroy_function,
		},
		.hash = hash,
		.equals = equals,
	);

	init_hashtable(this, capacity);

	return &this->public;
}
