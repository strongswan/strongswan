/*
 * Copyright (C) 2010-2014 Tobias Brunner
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

#define _GNU_SOURCE
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif /* HAVE_GLOB_H */

#include "settings.h"

#include "collections/array.h"
#include "collections/hashtable.h"
#include "collections/linked_list.h"
#include "threading/rwlock.h"
#include "utils/debug.h"

#define MAX_INCLUSION_LEVEL		10

typedef struct private_settings_t private_settings_t;
typedef struct section_t section_t;
typedef struct kv_t kv_t;

/**
 * private data of settings
 */
struct private_settings_t {

	/**
	 * public functions
	 */
	settings_t public;

	/**
	 * top level section
	 */
	section_t *top;

	/**
	 * contents of loaded files and in-memory settings (char*)
	 */
	linked_list_t *contents;

	/**
	 * lock to safely access the settings
	 */
	rwlock_t *lock;
};

/**
 * section containing subsections and key value pairs
 */
struct section_t {

	/**
	 * name of the section
	 */
	char *name;

	/**
	 * fallback sections, as section_t
	 */
	array_t *fallbacks;

	/**
	 * subsections, as section_t
	 */
	array_t *sections;

	/**
	 * key value pairs, as kv_t
	 */
	array_t *kv;
};

/**
 * Key value pair
 */
struct kv_t {

	/**
	 * key string, relative
	 */
	char *key;

	/**
	 * value as string
	 */
	char *value;
};

/**
 * create a key/value pair
 */
static kv_t *kv_create(char *key, char *value)
{
	kv_t *this;
	INIT(this,
		.key = strdup(key),
		.value = value,
	);
	return this;
}

/**
 * destroy a key/value pair
 */
static void kv_destroy(kv_t *this)
{
	free(this->key);
	free(this);
}

/**
 * create a section with the given name
 */
static section_t *section_create(char *name)
{
	section_t *this;
	INIT(this,
		.name = strdupnull(name),
	);
	return this;
}

/**
 * destroy a section
 */
static void section_destroy(section_t *this)
{
	array_destroy_function(this->sections, (void*)section_destroy, NULL);
	array_destroy_function(this->kv, (void*)kv_destroy, NULL);
	array_destroy(this->fallbacks);
	free(this->name);
	free(this);
}

/**
 * Purge contents of a section, returns if section can be safely removed.
 */
static bool section_purge(section_t *this)
{
	section_t *current;
	int i;

	array_destroy_function(this->kv, (void*)kv_destroy, NULL);
	this->kv = NULL;
	/* we ensure sections used as fallback, or configured with fallbacks (or
	 * having any such subsections) are not removed */
	for (i = array_count(this->sections) - 1; i >= 0; i--)
	{
		array_get(this->sections, i, &current);
		if (section_purge(current))
		{
			array_remove(this->sections, i, NULL);
			section_destroy(current);
		}
	}
	return !this->fallbacks && !array_count(this->sections);
}

/**
 * callback to find a section by name
 */
static int section_find(const void *a, const void *b)
{
	const char *key = a;
	const section_t *item = b;
	return strcmp(key, item->name);
}

/**
 * callback to sort sections by name
 */
static int section_sort(const void *a, const void *b, void *user)
{
	const section_t *sa = a, *sb = b;
	return strcmp(sa->name, sb->name);
}

/**
 * callback to find a kv pair by key
 */
static int kv_find(const void *a, const void *b)
{
	const char *key = a;
	const kv_t *item = b;
	return strcmp(key, item->key);
}

/**
 * callback to sort kv pairs by key
 */
static int kv_sort(const void *a, const void *b, void *user)
{
	const kv_t *kva = a, *kvb = b;
	return strcmp(kva->key, kvb->key);
}

/**
 * Print a format key, but consume already processed arguments
 */
static bool print_key(char *buf, int len, char *start, char *key, va_list args)
{
	va_list copy;
	char *pos = start;
	bool res;

	va_copy(copy, args);
	while (TRUE)
	{
		pos = memchr(pos, '%', key - pos);
		if (!pos)
		{
			break;
		}
		pos++;
		switch (*pos)
		{
			case 'd':
				va_arg(copy, int);
				break;
			case 's':
				va_arg(copy, char*);
				break;
			case 'N':
				va_arg(copy, enum_name_t*);
				va_arg(copy, int);
				break;
			case '%':
				break;
			default:
				DBG1(DBG_CFG, "settings with %%%c not supported!", *pos);
				break;
		}
		pos++;
	}
	res = vsnprintf(buf, len, key, copy) < len;
	va_end(copy);
	return res;
}

/**
 * Find a section by a given key, using buffered key, reusable buffer.
 * If "ensure" is TRUE, the sections are created if they don't exist.
 */
static section_t *find_section_buffered(section_t *section,
					char *start, char *key, va_list args, char *buf, int len,
					bool ensure)
{
	char *pos;
	section_t *found = NULL;

	if (section == NULL)
	{
		return NULL;
	}
	pos = strchr(key, '.');
	if (pos)
	{
		*pos = '\0';
		pos++;
	}
	if (!print_key(buf, len, start, key, args))
	{
		return NULL;
	}
	if (!strlen(buf))
	{
		found = section;
	}
	else if (array_bsearch(section->sections, buf, section_find, &found) == -1)
	{
		if (ensure)
		{
			found = section_create(buf);
			array_insert_create(&section->sections, ARRAY_TAIL, found);
			array_sort(section->sections, section_sort, NULL);
		}
	}
	if (found && pos)
	{
		return find_section_buffered(found, start, pos, args, buf, len, ensure);
	}
	return found;
}

/**
 * Find all sections via a given key considering fallbacks, using buffered key,
 * reusable buffer.
 */
static void find_sections_buffered(section_t *section, char *start, char *key,
						va_list args, char *buf, int len, array_t **sections)
{
	section_t *found = NULL, *fallback;
	char *pos;
	int i;

	if (!section)
	{
		return;
	}
	pos = strchr(key, '.');
	if (pos)
	{
		*pos = '\0';
	}
	if (!print_key(buf, len, start, key, args))
	{
		return;
	}
	if (pos)
	{	/* restore so we can follow fallbacks */
		*pos = '.';
	}
	if (!strlen(buf))
	{
		found = section;
	}
	else
	{
		array_bsearch(section->sections, buf, section_find, &found);
	}
	if (found)
	{
		if (pos)
		{
			find_sections_buffered(found, start, pos+1, args, buf, len,
								   sections);
		}
		else
		{
			array_insert_create(sections, ARRAY_TAIL, found);
			for (i = 0; i < array_count(found->fallbacks); i++)
			{
				array_get(found->fallbacks, i, &fallback);
				array_insert_create(sections, ARRAY_TAIL, fallback);
			}
		}
	}
	if (section->fallbacks)
	{
		for (i = 0; i < array_count(section->fallbacks); i++)
		{
			array_get(section->fallbacks, i, &fallback);
			find_sections_buffered(fallback, start, key, args, buf, len,
								   sections);
		}
	}
}

/**
 * Ensure that the section with the given key exists (thread-safe).
 */
static section_t *ensure_section(private_settings_t *this, section_t *section,
								 const char *key, va_list args)
{
	char buf[128], keybuf[512];
	section_t *found;

	if (snprintf(keybuf, sizeof(keybuf), "%s", key) >= sizeof(keybuf))
	{
		return NULL;
	}
	/* we might have to change the tree */
	this->lock->write_lock(this->lock);
	found = find_section_buffered(section, keybuf, keybuf, args, buf,
								  sizeof(buf), TRUE);
	this->lock->unlock(this->lock);
	return found;
}

/**
 * Find a section by a given key with its fallbacks (not thread-safe!).
 * Sections are returned in depth-first order (array is allocated). NULL is
 * returned if no sections are found.
 */
static array_t *find_sections(private_settings_t *this, section_t *section,
							  char *key, va_list args)
{
	char buf[128], keybuf[512];
	array_t *sections = NULL;

	if (snprintf(keybuf, sizeof(keybuf), "%s", key) >= sizeof(keybuf))
	{
		return NULL;
	}
	find_sections_buffered(section, keybuf, keybuf, args, buf,
						   sizeof(buf), &sections);
	return sections;
}

/**
 * Check if the given fallback section already exists
 */
static bool fallback_exists(section_t *section, section_t *fallback)
{
	if (section == fallback)
	{
		return TRUE;
	}
	else if (section->fallbacks)
	{
		section_t *existing;
		int i;

		for (i = 0; i < array_count(section->fallbacks); i++)
		{
			array_get(section->fallbacks, i, &existing);
			if (existing == fallback)
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}

/**
 * Ensure that the section with the given key exists and add the given fallback
 * section (thread-safe).
 */
static void add_fallback_to_section(private_settings_t *this,
							section_t *section, const char *key, va_list args,
							section_t *fallback)
{
	char buf[128], keybuf[512];
	section_t *found;

	if (snprintf(keybuf, sizeof(keybuf), "%s", key) >= sizeof(keybuf))
	{
		return;
	}
	this->lock->write_lock(this->lock);
	found = find_section_buffered(section, keybuf, keybuf, args, buf,
								  sizeof(buf), TRUE);
	if (!fallback_exists(found, fallback))
	{
		/* to ensure sections referred to as fallback are not purged, we create
		 * the array there too */
		if (!fallback->fallbacks)
		{
			fallback->fallbacks = array_create(0, 0);
		}
		array_insert_create(&found->fallbacks, ARRAY_TAIL, fallback);
	}
	this->lock->unlock(this->lock);
}

/**
 * Find the key/value pair for a key, using buffered key, reusable buffer
 * If "ensure" is TRUE, the sections (and key/value pair) are created if they
 * don't exist.
 * Fallbacks are only considered if "ensure" is FALSE.
 */
static kv_t *find_value_buffered(section_t *section, char *start, char *key,
								 va_list args, char *buf, int len, bool ensure)
{
	int i;
	char *pos;
	kv_t *kv = NULL;
	section_t *found = NULL;

	if (section == NULL)
	{
		return NULL;
	}

	pos = strchr(key, '.');
	if (pos)
	{
		*pos = '\0';
		if (!print_key(buf, len, start, key, args))
		{
			return NULL;
		}
		/* restore so we can retry for fallbacks */
		*pos = '.';
		if (!strlen(buf))
		{
			found = section;
		}
		else if (array_bsearch(section->sections, buf, section_find,
							   &found) == -1)
		{
			if (ensure)
			{
				found = section_create(buf);
				array_insert_create(&section->sections, ARRAY_TAIL, found);
				array_sort(section->sections, section_sort, NULL);
			}
		}
		if (found)
		{
			kv = find_value_buffered(found, start, pos+1, args, buf, len,
									 ensure);
		}
		if (!kv && !ensure && section->fallbacks)
		{
			for (i = 0; !kv && i < array_count(section->fallbacks); i++)
			{
				array_get(section->fallbacks, i, &found);
				kv = find_value_buffered(found, start, key, args, buf, len,
										 ensure);
			}
		}
	}
	else
	{
		if (!print_key(buf, len, start, key, args))
		{
			return NULL;
		}
		if (array_bsearch(section->kv, buf, kv_find, &kv) == -1)
		{
			if (ensure)
			{
				kv = kv_create(buf, NULL);
				array_insert_create(&section->kv, ARRAY_TAIL, kv);
				array_sort(section->kv, kv_sort, NULL);
			}
			else if (section->fallbacks)
			{
				for (i = 0; !kv && i < array_count(section->fallbacks); i++)
				{
					array_get(section->fallbacks, i, &found);
					kv = find_value_buffered(found, start, key, args, buf, len,
											 ensure);
				}
			}
		}
	}
	return kv;
}

/**
 * Find the string value for a key (thread-safe).
 */
static char *find_value(private_settings_t *this, section_t *section,
						char *key, va_list args)
{
	char buf[128], keybuf[512], *value = NULL;
	kv_t *kv;

	if (snprintf(keybuf, sizeof(keybuf), "%s", key) >= sizeof(keybuf))
	{
		return NULL;
	}
	this->lock->read_lock(this->lock);
	kv = find_value_buffered(section, keybuf, keybuf, args, buf, sizeof(buf),
							 FALSE);
	if (kv)
	{
		value = kv->value;
	}
	this->lock->unlock(this->lock);
	return value;
}

/**
 * Set a value to a copy of the given string (thread-safe).
 */
static void set_value(private_settings_t *this, section_t *section,
					  char *key, va_list args, char *value)
{
	char buf[128], keybuf[512];
	kv_t *kv;

	if (snprintf(keybuf, sizeof(keybuf), "%s", key) >= sizeof(keybuf))
	{
		return;
	}
	this->lock->write_lock(this->lock);
	kv = find_value_buffered(section, keybuf, keybuf, args, buf, sizeof(buf),
							 TRUE);
	if (kv)
	{
		if (!value)
		{
			kv->value = NULL;
		}
		else if (kv->value && (strlen(value) <= strlen(kv->value)))
		{	/* overwrite in-place, if possible */
			strcpy(kv->value, value);
		}
		else
		{	/* otherwise clone the string and store it in the cache */
			kv->value = strdup(value);
			this->contents->insert_last(this->contents, kv->value);
		}
	}
	this->lock->unlock(this->lock);
}

METHOD(settings_t, get_str, char*,
	private_settings_t *this, char *key, char *def, ...)
{
	char *value;
	va_list args;

	va_start(args, def);
	value = find_value(this, this->top, key, args);
	va_end(args);
	if (value)
	{
		return value;
	}
	return def;
}

/**
 * Described in header
 */
inline bool settings_value_as_bool(char *value, bool def)
{
	if (value)
	{
		if (strcaseeq(value, "1") ||
			strcaseeq(value, "yes") ||
			strcaseeq(value, "true") ||
			strcaseeq(value, "enabled"))
		{
			return TRUE;
		}
		else if (strcaseeq(value, "0") ||
				 strcaseeq(value, "no") ||
				 strcaseeq(value, "false") ||
				 strcaseeq(value, "disabled"))
		{
			return FALSE;
		}
	}
	return def;
}

METHOD(settings_t, get_bool, bool,
	private_settings_t *this, char *key, bool def, ...)
{
	char *value;
	va_list args;

	va_start(args, def);
	value = find_value(this, this->top, key, args);
	va_end(args);
	return settings_value_as_bool(value, def);
}

/**
 * Described in header
 */
inline int settings_value_as_int(char *value, int def)
{
	int intval;
	if (value)
	{
		errno = 0;
		intval = strtol(value, NULL, 10);
		if (errno == 0)
		{
			return intval;
		}
	}
	return def;
}

METHOD(settings_t, get_int, int,
	private_settings_t *this, char *key, int def, ...)
{
	char *value;
	va_list args;

	va_start(args, def);
	value = find_value(this, this->top, key, args);
	va_end(args);
	return settings_value_as_int(value, def);
}

/**
 * Described in header
 */
inline double settings_value_as_double(char *value, double def)
{
	double dval;
	if (value)
	{
		errno = 0;
		dval = strtod(value, NULL);
		if (errno == 0)
		{
			return dval;
		}
	}
	return def;
}

METHOD(settings_t, get_double, double,
	private_settings_t *this, char *key, double def, ...)
{
	char *value;
	va_list args;

	va_start(args, def);
	value = find_value(this, this->top, key, args);
	va_end(args);
	return settings_value_as_double(value, def);
}

/**
 * Described in header
 */
inline u_int32_t settings_value_as_time(char *value, u_int32_t def)
{
	char *endptr;
	u_int32_t timeval;
	if (value)
	{
		errno = 0;
		timeval = strtoul(value, &endptr, 10);
		if (errno == 0)
		{
			switch (*endptr)
			{
				case 'd':		/* time in days */
					timeval *= 24 * 3600;
					break;
				case 'h':		/* time in hours */
					timeval *= 3600;
					break;
				case 'm':		/* time in minutes */
					timeval *= 60;
					break;
				case 's':		/* time in seconds */
				default:
					break;
			}
			return timeval;
		}
	}
	return def;
}

METHOD(settings_t, get_time, u_int32_t,
	private_settings_t *this, char *key, u_int32_t def, ...)
{
	char *value;
	va_list args;

	va_start(args, def);
	value = find_value(this, this->top, key, args);
	va_end(args);
	return settings_value_as_time(value, def);
}

METHOD(settings_t, set_str, void,
	private_settings_t *this, char *key, char *value, ...)
{
	va_list args;
	va_start(args, value);
	set_value(this, this->top, key, args, value);
	va_end(args);
}

METHOD(settings_t, set_bool, void,
	private_settings_t *this, char *key, bool value, ...)
{
	va_list args;
	va_start(args, value);
	set_value(this, this->top, key, args, value ? "1" : "0");
	va_end(args);
}

METHOD(settings_t, set_int, void,
	private_settings_t *this, char *key, int value, ...)
{
	char val[16];
	va_list args;
	va_start(args, value);
	if (snprintf(val, sizeof(val), "%d", value) < sizeof(val))
	{
		set_value(this, this->top, key, args, val);
	}
	va_end(args);
}

METHOD(settings_t, set_double, void,
	private_settings_t *this, char *key, double value, ...)
{
	char val[64];
	va_list args;
	va_start(args, value);
	if (snprintf(val, sizeof(val), "%f", value) < sizeof(val))
	{
		set_value(this, this->top, key, args, val);
	}
	va_end(args);
}

METHOD(settings_t, set_time, void,
	private_settings_t *this, char *key, u_int32_t value, ...)
{
	char val[16];
	va_list args;
	va_start(args, value);
	if (snprintf(val, sizeof(val), "%u", value) < sizeof(val))
	{
		set_value(this, this->top, key, args, val);
	}
	va_end(args);
}

METHOD(settings_t, set_default_str, bool,
	private_settings_t *this, char *key, char *value, ...)
{
	char *old;
	va_list args;

	va_start(args, value);
	old = find_value(this, this->top, key, args);
	va_end(args);

	if (!old)
	{
		va_start(args, value);
		set_value(this, this->top, key, args, value);
		va_end(args);
		return TRUE;
	}
	return FALSE;
}

/**
 * Data for enumerators
 */
typedef struct {
	/** settings_t instance */
	private_settings_t *settings;
	/** sections to enumerate */
	array_t *sections;
	/** sections/keys that were already enumerated */
	hashtable_t *seen;
} enumerator_data_t;

/**
 * Destroy enumerator data
 */
static void enumerator_destroy(enumerator_data_t *this)
{
	this->settings->lock->unlock(this->settings->lock);
	this->seen->destroy(this->seen);
	array_destroy(this->sections);
	free(this);
}

/**
 * Enumerate section names, not sections
 */
static bool section_filter(hashtable_t *seen, section_t **in, char **out)
{
	*out = (*in)->name;
	if (seen->get(seen, *out))
	{
		return FALSE;
	}
	seen->put(seen, *out, *out);
	return TRUE;
}

/**
 * Enumerate sections of the given section
 */
static enumerator_t *section_enumerator(section_t *section,
										enumerator_data_t *data)
{
	return enumerator_create_filter(array_create_enumerator(section->sections),
				(void*)section_filter, data->seen, NULL);
}

METHOD(settings_t, create_section_enumerator, enumerator_t*,
	private_settings_t *this, char *key, ...)
{
	enumerator_data_t *data;
	array_t *sections;
	va_list args;

	this->lock->read_lock(this->lock);
	va_start(args, key);
	sections = find_sections(this, this->top, key, args);
	va_end(args);

	if (!sections)
	{
		this->lock->unlock(this->lock);
		return enumerator_create_empty();
	}
	INIT(data,
		.settings = this,
		.sections = sections,
		.seen = hashtable_create(hashtable_hash_str, hashtable_equals_str, 8),
	);
	return enumerator_create_nested(array_create_enumerator(sections),
					(void*)section_enumerator, data, (void*)enumerator_destroy);
}

/**
 * Enumerate key and values, not kv_t entries
 */
static bool kv_filter(hashtable_t *seen, kv_t **in, char **key,
					  void *none, char **value)
{
	*key = (*in)->key;
	if (seen->get(seen, *key))
	{
		return FALSE;
	}
	*value = (*in)->value;
	seen->put(seen, *key, *key);
	return TRUE;
}

/**
 * Enumerate key/value pairs of the given section
 */
static enumerator_t *kv_enumerator(section_t *section, enumerator_data_t *data)
{
	return enumerator_create_filter(array_create_enumerator(section->kv),
					(void*)kv_filter, data->seen, NULL);
}

METHOD(settings_t, create_key_value_enumerator, enumerator_t*,
	private_settings_t *this, char *key, ...)
{
	enumerator_data_t *data;
	array_t *sections;
	va_list args;

	this->lock->read_lock(this->lock);
	va_start(args, key);
	sections = find_sections(this, this->top, key, args);
	va_end(args);

	if (!sections)
	{
		this->lock->unlock(this->lock);
		return enumerator_create_empty();
	}
	INIT(data,
		.settings = this,
		.sections = sections,
		.seen = hashtable_create(hashtable_hash_str, hashtable_equals_str, 8),
	);
	return enumerator_create_nested(array_create_enumerator(sections),
					(void*)kv_enumerator, data, (void*)enumerator_destroy);
}

METHOD(settings_t, add_fallback, void,
	private_settings_t *this, const char *key, const char *fallback, ...)
{
	section_t *section;
	va_list args;

	/* find/create the fallback */
	va_start(args, fallback);
	section = ensure_section(this, this->top, fallback, args);
	va_end(args);

	va_start(args, fallback);
	add_fallback_to_section(this, this->top, key, args, section);
	va_end(args);
}

/**
 * parse text, truncate "skip" chars, delimited by term respecting brackets.
 *
 * Chars in "skip" are truncated at the beginning and the end of the resulting
 * token. "term" contains a list of characters to read up to (first match),
 * while "br" contains bracket counterparts found in "term" to skip.
 */
static char parse(char **text, char *skip, char *term, char *br, char **token)
{
	char *best = NULL;
	char best_term = '\0';

	/* skip leading chars */
	while (strchr(skip, **text))
	{
		(*text)++;
		if (!**text)
		{
			return 0;
		}
	}
	/* mark begin of subtext */
	*token = *text;
	while (*term)
	{
		char *pos = *text;
		int level = 1;

		/* find terminator */
		while (*pos)
		{
			if (*pos == *term)
			{
				level--;
			}
			else if (br && *pos == *br)
			{
				level++;
			}
			if (level == 0)
			{
				if (best == NULL || best > pos)
				{
					best = pos;
					best_term = *term;
				}
				break;
			}
			pos++;
		}
		/* try next terminator */
		term++;
		if (br)
		{
			br++;
		}
	}
	if (best)
	{
		/* update input */
		*text = best;
		/* null trailing bytes */
		do
		{
			*best = '\0';
			best--;
		}
		while (best >= *token && strchr(skip, *best));
		/* return found terminator */
		return best_term;
	}
	return 0;
}

/**
 * Check if "text" starts with "pattern".
 * Characters in "skip" are skipped first. If found, TRUE is returned and "text"
 * is modified to point to the character right after "pattern".
 */
static bool starts_with(char **text, char *skip, char *pattern)
{
	char *pos = *text;
	int len = strlen(pattern);
	while (strchr(skip, *pos))
	{
		pos++;
		if (!*pos)
		{
			return FALSE;
		}
	}
	if (strlen(pos) < len || !strneq(pos, pattern, len))
	{
		return FALSE;
	}
	*text = pos + len;
	return TRUE;
}

/**
 * Check if what follows in "text" is an include statement.
 * If this function returns TRUE, "text" will point to the character right after
 * the include pattern, which is returned in "pattern".
 */
static bool parse_include(char **text, char **pattern)
{
	char *pos = *text;
	if (!starts_with(&pos, "\n\t ", "include"))
	{
		return FALSE;
	}
	if (starts_with(&pos, "\t ", "="))
	{	/* ignore "include = value" */
		return FALSE;
	}
	*text = pos;
	return parse(text, "\t ", "\n", NULL, pattern) != 0;
}

/**
 * Forward declaration.
 */
static bool parse_files(linked_list_t *contents, char *file, int level,
						char *pattern, section_t *section);

/**
 * Parse a section
 */
static bool parse_section(linked_list_t *contents, char *file, int level,
						  char **text, section_t *section)
{
	bool finished = FALSE;
	char *key, *value, *inner;

	while (!finished)
	{
		if (parse_include(text, &value))
		{
			if (!parse_files(contents, file, level, value, section))
			{
				DBG1(DBG_LIB, "failed to include '%s'", value);
				return FALSE;
			}
			continue;
		}
		switch (parse(text, "\t\n ", "{=#", NULL, &key))
		{
			case '{':
				if (parse(text, "\t ", "}", "{", &inner))
				{
					section_t *sub;
					if (!strlen(key))
					{
						DBG1(DBG_LIB, "skipping section without name in '%s'",
							 section->name);
						continue;
					}
					if (array_bsearch(section->sections, key, section_find,
									  &sub) == -1)
					{
						sub = section_create(key);
						if (parse_section(contents, file, level, &inner, sub))
						{
							array_insert_create(&section->sections, ARRAY_TAIL,
												sub);
							array_sort(section->sections, section_sort, NULL);
							continue;
						}
						section_destroy(sub);
					}
					else
					{	/* extend the existing section */
						if (parse_section(contents, file, level, &inner, sub))
						{
							continue;
						}
					}
					DBG1(DBG_LIB, "parsing subsection '%s' failed", key);
					break;
				}
				DBG1(DBG_LIB, "matching '}' not found near %s", *text);
				break;
			case '=':
				if (parse(text, "\t ", "\n", NULL, &value))
				{
					kv_t *kv;
					if (!strlen(key))
					{
						DBG1(DBG_LIB, "skipping value without key in '%s'",
							 section->name);
						continue;
					}
					if (array_bsearch(section->kv, key, kv_find, &kv) == -1)
					{
						kv = kv_create(key, value);
						array_insert_create(&section->kv, ARRAY_TAIL, kv);
						array_sort(section->kv, kv_sort, NULL);
					}
					else
					{	/* replace with the most recently read value */
						kv->value = value;
					}
					continue;
				}
				DBG1(DBG_LIB, "parsing value failed near %s", *text);
				break;
			case '#':
				parse(text, "", "\n", NULL, &value);
				continue;
			default:
				finished = TRUE;
				continue;
		}
		return FALSE;
	}
	return TRUE;
}

/**
 * Parse a file and add the settings to the given section.
 */
static bool parse_file(linked_list_t *contents, char *file, int level,
					   section_t *section)
{
	bool success;
	char *text, *pos;
	struct stat st;
	FILE *fd;
	int len;

	DBG2(DBG_LIB, "loading config file '%s'", file);
	if (stat(file, &st) == -1)
	{
		if (errno == ENOENT)
		{
			DBG2(DBG_LIB, "'%s' does not exist, ignored", file);
			return TRUE;
		}
		DBG1(DBG_LIB, "failed to stat '%s': %s", file, strerror(errno));
		return FALSE;
	}
	else if (!S_ISREG(st.st_mode))
	{
		DBG1(DBG_LIB, "'%s' is not a regular file", file);
		return FALSE;
	}
	fd = fopen(file, "r");
	if (fd == NULL)
	{
		DBG1(DBG_LIB, "'%s' is not readable", file);
		return FALSE;
	}
	fseek(fd, 0, SEEK_END);
	len = ftell(fd);
	rewind(fd);
	text = malloc(len + 1);
	text[len] = '\0';
	if (fread(text, 1, len, fd) != len)
	{
		free(text);
		fclose(fd);
		return FALSE;
	}
	fclose(fd);

	pos = text;
	success = parse_section(contents, file, level, &pos, section);
	if (!success)
	{
		free(text);
	}
	else
	{
		contents->insert_last(contents, text);
	}
	return success;
}

/**
 * Load the files matching "pattern", which is resolved with glob(3), if
 * available.
 * If the pattern is relative, the directory of "file" is used as base.
 */
static bool parse_files(linked_list_t *contents, char *file, int level,
						char *pattern, section_t *section)
{
	bool success = TRUE;
	char pat[PATH_MAX];

	if (level > MAX_INCLUSION_LEVEL)
	{
		DBG1(DBG_LIB, "maximum level of %d includes reached, ignored",
			 MAX_INCLUSION_LEVEL);
		return TRUE;
	}

	if (!strlen(pattern))
	{
		DBG2(DBG_LIB, "empty include pattern, ignored");
		return TRUE;
	}

	if (!file || pattern[0] == '/')
	{	/* absolute path */
		if (snprintf(pat, sizeof(pat), "%s", pattern) >= sizeof(pat))
		{
			DBG1(DBG_LIB, "include pattern too long, ignored");
			return TRUE;
		}
	}
	else
	{	/* base relative paths to the directory of the current file */
		char *dir = path_dirname(file);
		if (snprintf(pat, sizeof(pat), "%s/%s", dir, pattern) >= sizeof(pat))
		{
			DBG1(DBG_LIB, "include pattern too long, ignored");
			free(dir);
			return TRUE;
		}
		free(dir);
	}
#ifdef HAVE_GLOB_H
	{
		int status;
		glob_t buf;

		status = glob(pat, GLOB_ERR, NULL, &buf);
		if (status == GLOB_NOMATCH)
		{
			DBG2(DBG_LIB, "no files found matching '%s', ignored", pat);
		}
		else if (status != 0)
		{
			DBG1(DBG_LIB, "expanding file pattern '%s' failed", pat);
			success = FALSE;
		}
		else
		{
			char **expanded;
			for (expanded = buf.gl_pathv; *expanded != NULL; expanded++)
			{
				success &= parse_file(contents, *expanded, level + 1, section);
				if (!success)
				{
					break;
				}
			}
		}
		globfree(&buf);
	}
#else /* HAVE_GLOB_H */
	/* if glob(3) is not available, try to load pattern directly */
	success = parse_file(contents, pat, level + 1, section);
#endif /* HAVE_GLOB_H */
	return success;
}

/**
 * Recursivly extends "base" with "extension".
 */
static void section_extend(section_t *base, section_t *extension)
{
	enumerator_t *enumerator;
	section_t *sec;
	kv_t *kv;

	enumerator = array_create_enumerator(extension->sections);
	while (enumerator->enumerate(enumerator, (void**)&sec))
	{
		section_t *found;
		if (array_bsearch(base->sections, sec->name, section_find,
			&found) != -1)
		{
			section_extend(found, sec);
		}
		else
		{
			array_remove_at(extension->sections, enumerator);
			array_insert_create(&base->sections, ARRAY_TAIL, sec);
			array_sort(base->sections, section_sort, NULL);
		}
	}
	enumerator->destroy(enumerator);

	enumerator = array_create_enumerator(extension->kv);
	while (enumerator->enumerate(enumerator, (void**)&kv))
	{
		kv_t *found;
		if (array_bsearch(base->kv, kv->key, kv_find, &found) != -1)
		{
			found->value = kv->value;
		}
		else
		{
			array_remove_at(extension->kv, enumerator);
			array_insert_create(&base->kv, ARRAY_TAIL, kv);
			array_sort(base->kv, kv_sort, NULL);
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Load settings from files matching the given file pattern.
 * All sections and values are added relative to "parent".
 * All files (even included ones) have to be loaded successfully.
 */
static bool load_files_internal(private_settings_t *this, section_t *parent,
								char *pattern, bool merge)
{
	char *text;
	linked_list_t *contents;
	section_t *section;

	if (pattern == NULL)
	{
#ifdef STRONGSWAN_CONF
		pattern = STRONGSWAN_CONF;
#else
		return FALSE;
#endif
	}

	contents = linked_list_create();
	section = section_create(NULL);

	if (!parse_files(contents, NULL, 0, pattern, section))
	{
		contents->destroy_function(contents, (void*)free);
		section_destroy(section);
		return FALSE;
	}

	this->lock->write_lock(this->lock);
	if (!merge)
	{
		section_purge(parent);
	}
	/* extend parent section */
	section_extend(parent, section);
	/* move contents of loaded files to main store */
	while (contents->remove_first(contents, (void**)&text) == SUCCESS)
	{
		this->contents->insert_last(this->contents, text);
	}
	this->lock->unlock(this->lock);

	section_destroy(section);
	contents->destroy(contents);
	return TRUE;
}

METHOD(settings_t, load_files, bool,
	private_settings_t *this, char *pattern, bool merge)
{
	return load_files_internal(this, this->top, pattern, merge);
}

METHOD(settings_t, load_files_section, bool,
	private_settings_t *this, char *pattern, bool merge, char *key, ...)
{
	section_t *section;
	va_list args;

	va_start(args, key);
	section = ensure_section(this, this->top, key, args);
	va_end(args);

	if (!section)
	{
		return FALSE;
	}
	return load_files_internal(this, section, pattern, merge);
}

METHOD(settings_t, destroy, void,
	private_settings_t *this)
{
	section_destroy(this->top);
	this->contents->destroy_function(this->contents, (void*)free);
	this->lock->destroy(this->lock);
	free(this);
}

/*
 * see header file
 */
settings_t *settings_create(char *file)
{
	private_settings_t *this;

	INIT(this,
		.public = {
			.get_str = _get_str,
			.get_int = _get_int,
			.get_double = _get_double,
			.get_time = _get_time,
			.get_bool = _get_bool,
			.set_str = _set_str,
			.set_int = _set_int,
			.set_double = _set_double,
			.set_time = _set_time,
			.set_bool = _set_bool,
			.set_default_str = _set_default_str,
			.create_section_enumerator = _create_section_enumerator,
			.create_key_value_enumerator = _create_key_value_enumerator,
			.add_fallback = _add_fallback,
			.load_files = _load_files,
			.load_files_section = _load_files_section,
			.destroy = _destroy,
		},
		.top = section_create(NULL),
		.contents = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);

	load_files(this, file, FALSE);

	return &this->public;
}

