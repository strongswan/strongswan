/*
 * Copyright (C) 2010-2014 Tobias Brunner
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

#include "settings_types.h"

/*
 * Described in header
 */
kv_t *settings_kv_create(char *key, char *value)
{
	kv_t *this;

	INIT(this,
		.key = key,
		.value = value,
	);
	return this;
}

/*
 * Described in header
 */
void settings_kv_destroy(kv_t *this, array_t *contents)
{
	free(this->key);
	if (contents && this->value)
	{
		array_insert(contents, ARRAY_TAIL, this->value);
	}
	else
	{
		free(this->value);
	}
	free(this);
}

/*
 * Described in header
 */
section_t *settings_section_create(char *name)
{
	section_t *this;

	INIT(this,
		.name = name,
	);
	return this;
}

static void section_destroy(section_t *section, int idx, array_t *contents)
{
	settings_section_destroy(section, contents);
}

static void kv_destroy(kv_t *kv, int idx, array_t *contents)
{
	settings_kv_destroy(kv, contents);
}

/*
 * Described in header
 */
void settings_section_destroy(section_t *this, array_t *contents)
{
	array_destroy_function(this->sections, (void*)section_destroy, contents);
	array_destroy_function(this->kv, (void*)kv_destroy, contents);
	array_destroy(this->fallbacks);
	free(this->name);
	free(this);
}

/*
 * Described in header
 */
void settings_kv_set(kv_t *kv, char *value, array_t *contents)
{
	if (value && kv->value && streq(value, kv->value))
	{	/* no update required */
		free(value);
		return;
	}

	/* if the new value was shorter we could overwrite the existing one but that
	 * could lead to reads of partially updated values from other threads that
	 * have a pointer to the existing value, so we replace it anyway */
	if (kv->value && contents)
	{
		array_insert(contents, ARRAY_TAIL, kv->value);
	}
	else
	{
		free(kv->value);
	}
	kv->value = value;
}

/*
 * Described in header
 */
void settings_kv_add(section_t *section, kv_t *kv, array_t *contents)
{
	kv_t *found;

	if (array_bsearch(section->kv, kv->key, settings_kv_find, &found) == -1)
	{
		array_insert_create(&section->kv, ARRAY_TAIL, kv);
		array_sort(section->kv, settings_kv_sort, NULL);
	}
	else
	{
		settings_kv_set(found, kv->value, contents);
		kv->value = NULL;
		settings_kv_destroy(kv, NULL);
	}
}

/*
 * Described in header
 */
void settings_section_add(section_t *parent, section_t *section,
						  array_t *contents)
{
	section_t *found;

	if (array_bsearch(parent->sections, section->name, settings_section_find,
					  &found) == -1)
	{
		array_insert_create(&parent->sections, ARRAY_TAIL, section);
		array_sort(parent->sections, settings_section_sort, NULL);
	}
	else
	{
		settings_section_extend(found, section, contents);
		settings_section_destroy(section, contents);
	}
}

/*
 * Described in header
 */
void settings_section_extend(section_t *base, section_t *extension,
							 array_t *contents)
{
	enumerator_t *enumerator;
	section_t *section;
	kv_t *kv;

	enumerator = array_create_enumerator(extension->sections);
	while (enumerator->enumerate(enumerator, (void**)&section))
	{
		array_remove_at(extension->sections, enumerator);
		settings_section_add(base, section, contents);
	}
	enumerator->destroy(enumerator);

	enumerator = array_create_enumerator(extension->kv);
	while (enumerator->enumerate(enumerator, (void**)&kv))
	{
		array_remove_at(extension->kv, enumerator);
		settings_kv_add(base, kv, contents);
	}
	enumerator->destroy(enumerator);
}

/*
 * Described in header
 */
int settings_section_find(const void *a, const void *b)
{
	const char *key = a;
	const section_t *item = b;
	return strcmp(key, item->name);
}

/*
 * Described in header
 */
int settings_section_sort(const void *a, const void *b, void *user)
{
	const section_t *sa = a, *sb = b;
	return strcmp(sa->name, sb->name);
}

/*
 * Described in header
 */
int settings_kv_find(const void *a, const void *b)
{
	const char *key = a;
	const kv_t *item = b;
	return strcmp(key, item->key);
}

/*
 * Described in header
 */
int settings_kv_sort(const void *a, const void *b, void *user)
{
	const kv_t *kva = a, *kvb = b;
	return strcmp(kva->key, kvb->key);
}
