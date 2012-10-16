/*
 * Copyright (C) 2010 Tobias Brunner
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

#include <library.h>
#include <collections/hashtable.h>

static u_int hash(char *key)
{
	return chunk_hash(chunk_create(key, strlen(key)));
}

static u_int equals(char *key1, char *key2)
{
	return streq(key1, key2);
}

/**
 * Test the remove_at method
 */
bool test_hashtable_remove_at()
{
	char *k1 = "key1", *k2 = "key2", *k3 = "key3", *key;
	char *v1 = "val1", *v2 = "val2", *v3 = "val3", *value;
	enumerator_t *enumerator;
	hashtable_t *ht = hashtable_create((hashtable_hash_t)hash,
									   (hashtable_equals_t)equals, 0);

	ht->put(ht, k1, v1);
	ht->put(ht, k2, v2);
	ht->put(ht, k3, v3);

	if (ht->get_count(ht) != 3)
	{
		return FALSE;
	}

	enumerator = ht->create_enumerator(ht);
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		if (streq(key, k2))
		{
			ht->remove_at(ht, enumerator);
		}
	}
	enumerator->destroy(enumerator);

	if (ht->get_count(ht) != 2)
	{
		return FALSE;
	}

	if (ht->get(ht, k1) == NULL ||
		ht->get(ht, k3) == NULL)
	{
		return FALSE;
	}

	if (ht->get(ht, k2) != NULL)
	{
		return FALSE;
	}

	ht->put(ht, k2, v2);

	if (ht->get_count(ht) != 3)
	{
		return FALSE;
	}

	if (ht->get(ht, k1) == NULL ||
		ht->get(ht, k2) == NULL ||
		ht->get(ht, k3) == NULL)
	{
		return FALSE;
	}

	enumerator = ht->create_enumerator(ht);
	while (enumerator->enumerate(enumerator, &key, &value))
	{
		ht->remove_at(ht, enumerator);
	}
	enumerator->destroy(enumerator);

	if (ht->get_count(ht) != 0)
	{
		return FALSE;
	}

	if (ht->get(ht, k1) != NULL ||
		ht->get(ht, k2) != NULL ||
		ht->get(ht, k3) != NULL)
	{
		return FALSE;
	}

	ht->destroy(ht);

	return TRUE;
}
