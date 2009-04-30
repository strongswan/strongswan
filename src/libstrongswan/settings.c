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

#include <debug.h>
#include <utils/linked_list.h>


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
 * find a section by a given key
 */
static section_t *find_section(section_t *section, char *key, va_list args)
{
	char name[512], *pos;
	enumerator_t *enumerator;
	section_t *current, *found = NULL;
	
	if (section == NULL)
	{
		return NULL;
	}
	if (vsnprintf(name, sizeof(name), key, args) >= sizeof(name))
	{
		return NULL;
	}
	
	pos = strchr(name, '.');
	if (pos)
	{
		*pos = '\0';
		pos++;
	}
	enumerator = section->sections->create_enumerator(section->sections);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (streq(current->name, name))
		{
			found = current;
			break;
		}
	}
	enumerator->destroy(enumerator);
	if (found && pos)
	{
		return find_section(found, pos, args);
	}
	return found;
}

static char *find_value(section_t *section, char *key, va_list args)
{
	char name[512], *pos, *value = NULL;
	enumerator_t *enumerator;
	kv_t *kv;
	section_t *current, *found = NULL;
	
	if (section == NULL)
	{
		return NULL;
	}
	
	if (vsnprintf(name, sizeof(name), key, args) >= sizeof(name))
	{
		return NULL;
	}
	
	pos = strchr(name, '.');
	if (pos)
	{
		*pos = '\0';
		pos++;
		enumerator = section->sections->create_enumerator(section->sections);
		while (enumerator->enumerate(enumerator, &current))
		{
			if (streq(current->name, name))
			{
				found = current;
				break;
			}
		}
		enumerator->destroy(enumerator);
		if (found)
		{
			return find_value(found, pos, args);
		}
	}
	else
	{
		enumerator = section->kv->create_enumerator(section->kv);
		while (enumerator->enumerate(enumerator, &kv))
		{
			if (streq(kv->key, name))
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
 * Implementation of settings_t.get.
 */
static char* get_str(private_settings_t *this, char *key, char *def, ...)
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

/**
 * Implementation of settings_t.get_bool.
 */
static bool get_bool(private_settings_t *this, char *key, bool def, ...)
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

/**
 * Implementation of settings_t.get_int.
 */
static int get_int(private_settings_t *this, char *key, int def, ...)
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

/**
 * Implementation of settings_t.get_time.
 */
static u_int32_t get_time(private_settings_t *this, char *key, u_int32_t def, ...)
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
		timeval = strtol(value, &endptr, 10);
		if (errno == 0 && timeval >= 0)
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

/**
 * Implementation of settings_t.create_section_enumerator
 */
static enumerator_t* create_section_enumerator(private_settings_t *this,
											   char *key, ...)
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
				DBG1("matching '}' not found near %s", *text);
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
				DBG1("parsing value failed near %s", *text);
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

/**
 * Implementation of settings_t.destroy
 */
static void destroy(private_settings_t *this)
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
	private_settings_t *this = malloc_thing(private_settings_t);
	
	this->public.get_str = (char*(*)(settings_t*, char *key, char* def, ...))get_str;
	this->public.get_int = (int(*)(settings_t*, char *key, int def, ...))get_int;
	this->public.get_time = (u_int32_t(*)(settings_t*, char *key, u_int32_t def, ...))get_time;
	this->public.get_bool = (bool(*)(settings_t*, char *key, bool def, ...))get_bool;
	this->public.create_section_enumerator = (enumerator_t*(*)(settings_t*,char *section, ...))create_section_enumerator;
	this->public.destroy = (void(*)(settings_t*))destroy;
	
	this->top = NULL;
	this->text = NULL;
	
	if (file)
	{
		FILE *fd;
		int len;
		char *pos;
	
		fd = fopen(file, "r");
		if (fd == NULL)
		{
			DBG1("'%s' does not exist or is not readable", file);
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
			return &this->public;
		}
	}
	return &this->public;
}

