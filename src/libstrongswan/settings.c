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

#define _GNU_SOURCE
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>

#include "settings.h"

#include "debug.h"
#include "utils/linked_list.h"


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
	 * allocated file text
	 */
	char *text;
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
	 * subsections, as section_t
	 */
	linked_list_t *sections;

	/**
	 * key value pairs, as kv_t
	 */
	linked_list_t *kv;
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
 * Print a format key, but consume already processed arguments
 */
static bool print_key(char *buf, int len, char *start, char *key, va_list args)
{
	va_list copy;
	bool res;
	char *pos;

	va_copy(copy, args);
	while (start < key)
	{
		pos = strchr(start, '%');
		if (!pos)
		{
			start += strlen(start) + 1;
			continue;
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
		start = pos;
		if (*start)
		{
			start++;
		}
	}
	res = vsnprintf(buf, len, key, copy) < len;
	va_end(copy);
	return res;
}

/**
 * find a section by a given key, using buffered key, reusable buffer
 */
static section_t *find_section_buffered(section_t *section,
					char *start, char *key, va_list args, char *buf, int len)
{
	char *pos;
	enumerator_t *enumerator;
	section_t *current, *found = NULL;

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
	enumerator = section->sections->create_enumerator(section->sections);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (streq(current->name, buf))
		{
			found = current;
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (found && pos)
	{
		return find_section_buffered(found, start, pos, args, buf, len);
	}
	return found;
}

/**
 * find a section by a given key
 */
static section_t *find_section(section_t *section, char *key, va_list args)
{
	char buf[128], keybuf[512];

	if (snprintf(keybuf, sizeof(keybuf), "%s", key) >= sizeof(keybuf))
	{
		return NULL;
	}
	return find_section_buffered(section, keybuf, keybuf, args, buf, sizeof(buf));
}

/**
 * Find the string value for a key, using buffered key, reusable buffer
 */
static char *find_value_buffered(section_t *section,
					char *start, char *key, va_list args, char *buf, int len)
{
	char *pos, *value = NULL;
	enumerator_t *enumerator;
	kv_t *kv;
	section_t *current, *found = NULL;

	if (section == NULL)
	{
		return NULL;
	}

	pos = strchr(key, '.');
	if (pos)
	{
		*pos = '\0';
		pos++;

		if (!print_key(buf, len, start, key, args))
		{
			return NULL;
		}
		enumerator = section->sections->create_enumerator(section->sections);
		while (enumerator->enumerate(enumerator, &current))
		{
			if (streq(current->name, buf))
			{
				found = current;
				break;
			}
		}
		enumerator->destroy(enumerator);
		if (found)
		{
			return find_value_buffered(found, start, pos, args, buf, len);
		}
	}
	else
	{
		if (!print_key(buf, len, start, key, args))
		{
			return NULL;
		}
		enumerator = section->kv->create_enumerator(section->kv);
		while (enumerator->enumerate(enumerator, &kv))
		{
			if (streq(kv->key, buf))
			{
				value = kv->value;
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	return value;
}

/**
 * Find the string value for a key
 */
static char *find_value(section_t *section, char *key, va_list args)
{
	char buf[128], keybuf[512];

	if (snprintf(keybuf, sizeof(keybuf), "%s", key) >= sizeof(keybuf))
	{
		return NULL;
	}
	return find_value_buffered(section, keybuf, keybuf, args, buf, sizeof(buf));
}

METHOD(settings_t, get_str, char*,
	private_settings_t *this, char *key, char *def, ...)
{
	char *value;
	va_list args;

	va_start(args, def);
	value = find_value(this->top, key, args);
	va_end(args);
	if (value)
	{
		return value;
	}
	return def;
}

METHOD(settings_t, get_bool, bool,
	private_settings_t *this, char *key, bool def, ...)
{
	char *value;
	va_list args;

	va_start(args, def);
	value = find_value(this->top, key, args);
	va_end(args);
	if (value)
	{
		if (strcaseeq(value, "true") ||
			strcaseeq(value, "enabled") ||
			strcaseeq(value, "yes") ||
			strcaseeq(value, "1"))
		{
			return TRUE;
		}
		else if (strcaseeq(value, "false") ||
				 strcaseeq(value, "disabled") ||
				 strcaseeq(value, "no") ||
				 strcaseeq(value, "0"))
		{
			return FALSE;
		}
	}
	return def;
}

METHOD(settings_t, get_int, int,
	private_settings_t *this, char *key, int def, ...)
{
	char *value;
	int intval;
	va_list args;

	va_start(args, def);
	value = find_value(this->top, key, args);
	va_end(args);
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

METHOD(settings_t, get_double, double,
	private_settings_t *this, char *key, double def, ...)
{
	char *value;
	double dval;
	va_list args;

	va_start(args, def);
	value = find_value(this->top, key, args);
	va_end(args);
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

METHOD(settings_t, get_time, u_int32_t,
	private_settings_t *this, char *key, u_int32_t def, ...)
{
	char *value, *endptr;
	u_int32_t timeval;
	va_list args;

	va_start(args, def);
	value = find_value(this->top, key, args);
	va_end(args);
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

/**
 * Enumerate section names, not sections
 */
static bool section_filter(void *null, section_t **in, char **out)
{
	*out = (*in)->name;
	return TRUE;
}

METHOD(settings_t, create_section_enumerator, enumerator_t*,
	private_settings_t *this, char *key, ...)
{
	section_t *section;
	va_list args;

	va_start(args, key);
	section = find_section(this->top, key, args);
	va_end(args);

	if (!section)
	{
		return enumerator_create_empty();
	}
	return enumerator_create_filter(
					section->sections->create_enumerator(section->sections),
					(void*)section_filter, NULL, NULL);
}

/**
 * Enumerate key and values, not kv_t entries
 */
static bool kv_filter(void *null, kv_t **in, char **key,
					  void *none, char **value)
{
	*key = (*in)->key;
	*value = (*in)->value;
	return TRUE;
}

METHOD(settings_t, create_key_value_enumerator, enumerator_t*,
	private_settings_t *this, char *key, ...)
{
	section_t *section;
	va_list args;

	va_start(args, key);
	section = find_section(this->top, key, args);
	va_end(args);

	if (!section)
	{
		return enumerator_create_empty();
	}
	return enumerator_create_filter(
					section->kv->create_enumerator(section->kv),
					(void*)kv_filter, NULL, NULL);
}

/**
 * destroy a section
 */
static void section_destroy(section_t *this)
{
	this->kv->destroy_function(this->kv, free);
	this->sections->destroy_function(this->sections, (void*)section_destroy);

	free(this);
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
 * Parse a section
 */
static section_t* parse_section(char **text, char *name)
{
	section_t *sub, *section;
	bool finished = FALSE;
	char *key, *value, *inner;

	static int lev = 0;
	lev++;

	section = malloc_thing(section_t);
	section->name = name;
	section->sections = linked_list_create();
	section->kv = linked_list_create();

	while (!finished)
	{
		switch (parse(text, "\t\n ", "{=#", NULL, &key))
		{
			case '{':
				if (parse(text, "\t ", "}", "{", &inner))
				{
					sub = parse_section(&inner, key);
					if (sub)
					{
						section->sections->insert_last(section->sections, sub);
						continue;
					}
				}
				DBG1(DBG_LIB, "matching '}' not found near %s", *text);
				break;
			case '=':
				if (parse(text, "\t ", "\n", NULL, &value))
				{
					kv_t *kv = malloc_thing(kv_t);
					kv->key = key;
					kv->value = value;
					section->kv->insert_last(section->kv, kv);
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
		section_destroy(section);
		return NULL;
	}
	return section;
}

METHOD(settings_t, destroy, void,
	private_settings_t *this)
{
	if (this->top)
	{
		section_destroy(this->top);
	}
	free(this->text);
	free(this);
}

/*
 * see header file
 */
settings_t *settings_create(char *file)
{
	private_settings_t *this;
	char *pos;
	FILE *fd;
	int len;

	INIT(this,
		.public = {
			.get_str = _get_str,
			.get_int = _get_int,
			.get_double = _get_double,
			.get_time = _get_time,
			.get_bool = _get_bool,
			.create_section_enumerator = _create_section_enumerator,
			.create_key_value_enumerator = _create_key_value_enumerator,
			.destroy = _destroy,
		},
	);

	if (file == NULL)
	{
		file = STRONGSWAN_CONF;
	}
	fd = fopen(file, "r");
	if (fd == NULL)
	{
		DBG1(DBG_LIB, "'%s' does not exist or is not readable", file);
		return &this->public;
	}
	fseek(fd, 0, SEEK_END);
	len = ftell(fd);
	rewind(fd);
	this->text = malloc(len + 1);
	this->text[len] = '\0';
	if (fread(this->text, 1, len, fd) != len)
	{
		free(this->text);
		this->text = NULL;
		return &this->public;
	}
	fclose(fd);

	pos = this->text;
	this->top = parse_section(&pos, NULL);
	if (this->top == NULL)
	{
		free(this->text);
		this->text = NULL;
	}
	return &this->public;
}

