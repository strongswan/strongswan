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

/** The minimum size of the hash table (MUST be a power of 2) */
#define MIN_SIZE 8
/** The maximum size of the hash table (MUST be a power of 2) */
#define MAX_SIZE (1 << 30)
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
	 * The current size of the hash table (always a power of 2).
	 */
	u_int size;

	/**
	 * The current mask to calculate the row index (size - 1).
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

	/**
	 * Alternative comparison function.
	 */
	hashtable_cmp_t cmp;
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
static void init_hashtable(private_hashtable_t *this, u_int size)
{
	size = max(MIN_SIZE, min(size, MAX_SIZE));
	this->size = get_nearest_powerof2(size);
	this->mask = this->size - 1;

	this->table = calloc(this->size, sizeof(pair_t*));
}

/**
 * Double the size of the hash table and rehash all the elements.
 */
static void rehash(private_hashtable_t *this)
{
	pair_t **old_table, *to_move, *pair, *next;
	u_int row, new_row, old_size;

	if (this->size >= MAX_SIZE)
	{
		return;
	}

	old_size = this->size;
	old_table = this->table;

	init_hashtable(this, old_size << 1);

	for (row = 0; row < old_size; row++)
	{
		to_move = old_table[row];
		while (to_move)
		{
			pair_t *prev = NULL;

			new_row = to_move->hash & this->mask;
			pair = this->table[new_row];
			while (pair)
			{
				if (this->cmp && this->cmp(to_move->key, pair->key) < 0)
				{
					break;
				}
				prev = pair;
				pair = pair->next;
			}
			next = to_move->next;
			to_move->next = NULL;
			if (prev)
			{
				to_move->next = prev->next;
				prev->next = to_move;
			}
			else
			{
				to_move->next = this->table[new_row];
				this->table[new_row] = to_move;
			}
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
	bool use_callback = equals != NULL;
	u_int hash;

	if (!this->count && !out_hash)
	{	/* no need to calculate the hash if not requested */
		return NULL;
	}

	equals = equals ?: this->equals;
	hash = this->hash(key);
	if (out_hash)
	{
		*out_hash = hash;
	}

	pair = this->table[hash & this->mask];
	while (pair)
	{
		/* when keys are ordered, we compare all items so we can abort earlier
		 * even if the hash does not match, but only as long as we don't
		 * have a callback */
		if (!use_callback && this->cmp)
		{
			int cmp = this->cmp(key, pair->key);
			if (cmp == 0)
			{
				break;
			}
			else if (cmp < 0)
			{	/* no need to continue as the key we search is smaller */
				pair = NULL;
				break;
			}
		}
		else if (hash == pair->hash && equals(key, pair->key))
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

	if (this->count >= this->size * LOAD_FACTOR)
	{
		rehash(this);
	}

	pair = find_key(this, key, NULL, &hash, &prev);
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
			pair->next = prev->next;
			prev->next = pair;
		}
		else
		{
			pair->next = this->table[hash & this->mask];
			this->table[hash & this->mask] = pair;
		}
		this->count++;
	}
	return old_value;
}


METHOD(hashtable_t, get, void*,
	private_hashtable_t *this, const void *key)
{
	pair_t *pair = find_key(this, key, NULL, NULL, NULL);
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

	pair = find_key(this, key, NULL, NULL, &prev);
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

	while (this->count && this->row < this->table->size)
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

	for (row = 0; row < this->size; row++)
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

/**
 * Create a hash table
 */
static private_hashtable_t *hashtable_create_internal(hashtable_hash_t hash,
													  u_int size)
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
	);

	init_hashtable(this, size);

	return this;
}

/*
 * Described in header
 */
hashtable_t *hashtable_create(hashtable_hash_t hash, hashtable_equals_t equals,
							  u_int size)
{
	private_hashtable_t *this = hashtable_create_internal(hash, size);

	this->equals = equals;

	return &this->public;
}

/*
 * Described in header
 */
hashtable_t *hashtable_create_sorted(hashtable_hash_t hash,
									 hashtable_cmp_t cmp, u_int size)
{
	private_hashtable_t *this = hashtable_create_internal(hash, size);

	this->cmp = cmp;

	return &this->public;
}
