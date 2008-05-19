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
 *
 * $Id$
 */

#define _GNU_SOURCE
#include <string.h>
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

static char *find(section_t *section, char *key)
{
	char *name, *pos, *value = NULL;
	enumerator_t *enumerator;
	kv_t *kv;
	section_t *current, *found = NULL;
	
	if (section == NULL)
	{
		return NULL;
	}
	
	name = strdupa(key);
	
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
			return find(found, pos);
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
static char* get_str(private_settings_t *this, char *key, char *def)
{
	char *value;
	
	value = find(this->top, key);
	if (value)
	{
		return value;
	}
	return def;
}

/**
 * Implementation of settings_t.get_bool.
 */
static bool get_bool(private_settings_t *this, char *key, bool def)
{
	char *value;
	
	value = find(this->top, key);
	if (value)
	{
		if (strcasecmp(value, "true") == 0 ||
			strcasecmp(value, "enables") == 0 ||
			strcasecmp(value, "yes") == 0 ||
			strcasecmp(value, "1") == 0)
		{
			return TRUE;
		}
		else if (strcasecmp(value, "false") == 0 ||
				 strcasecmp(value, "disabled") == 0 ||
				 strcasecmp(value, "no") == 0 ||
				 strcasecmp(value, "0") == 0)
		{
			return FALSE;
		}
	}
	return def;
}

/**
 * Implementation of settings_t.get_int.
 */
static int get_int(private_settings_t *this, char *key, int def)
{
	char *value;
	int intval;
	
	value = find(this->top, key);
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
 * destry a section
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
	
	this->public.get_str = (char*(*)(settings_t*, char *key, char* def))get_str;
	this->public.get_int = (int(*)(settings_t*, char *key, bool def))get_int;
	this->public.get_bool = (bool(*)(settings_t*, char *key, bool def))get_bool;
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

