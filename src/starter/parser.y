%{
/* strongSwan config file parser (parser.y)
 * Copyright (C) 2001 Mathieu Lafon - Arkoon Network Security
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <library.h>
#include <utils/debug.h>

#include "ipsec-parser.h"

#define YYERROR_VERBOSE
#define ERRSTRING_LEN   256

/**
 * Bison
 */
static char parser_errstring[ERRSTRING_LEN+1];

extern void yyerror(const char *s);
extern int yylex (void);
extern void _parser_y_error(char *b, int size, const char *s);

/**
 * Static Globals
 */
static int _save_errors_;
static config_parsed_t *_parser_cfg;
static kw_list_t **_parser_kw, *_parser_kw_last;
static char errbuf[ERRSTRING_LEN+1];

/**
 * Gperf
 */
extern kw_entry_t *in_word_set (char *str, unsigned int len);

%}

%union { char *s; };
%token EQUAL FIRST_SPACES EOL CONFIG SETUP CONN CA INCLUDE FILE_VERSION
%token <s> STRING

%%

/*
 * Config file
 */

config_file:
	config_file section_or_include
	| /* NULL */
	;

section_or_include:
	FILE_VERSION STRING EOL
	{
		free($2);
	}
	| CONFIG SETUP EOL
	{
		_parser_kw = &(_parser_cfg->config_setup);
		_parser_kw_last = NULL;
	} kw_section
	| CONN STRING EOL
	{
		section_list_t *section = malloc_thing(section_list_t);

		section->name = strdupnull($2);
		section->kw = NULL;
		section->next = NULL;
		_parser_kw = &(section->kw);
		if (!_parser_cfg->conn_first)
			_parser_cfg->conn_first = section;
		if (_parser_cfg->conn_last)
			_parser_cfg->conn_last->next = section;
		_parser_cfg->conn_last = section;
		_parser_kw_last = NULL;
		free($2);
	} kw_section
	| CA STRING EOL
	{
		section_list_t *section = malloc_thing(section_list_t);
		section->name = strdupnull($2);
		section->kw = NULL;
		section->next = NULL;
		_parser_kw = &(section->kw);
		if (!_parser_cfg->ca_first)
			_parser_cfg->ca_first = section;
		if (_parser_cfg->ca_last)
			_parser_cfg->ca_last->next = section;
		_parser_cfg->ca_last = section;
		_parser_kw_last = NULL;
		free($2);
	} kw_section
	| INCLUDE STRING
	{
		extern void _parser_y_include (const char *f);
		_parser_y_include($2);
		free($2);
	} EOL
	| EOL
	;

kw_section:
	FIRST_SPACES statement_kw EOL kw_section
	|
	;

statement_kw:
	STRING EQUAL STRING
	{
		kw_list_t  *new;
		kw_entry_t *entry = in_word_set($1, strlen($1));

		if (entry == NULL)
		{
			snprintf(errbuf, ERRSTRING_LEN, "unknown keyword '%s'", $1);
			yyerror(errbuf);
		}
		else if (_parser_kw)
		{
			new = (kw_list_t *)malloc_thing(kw_list_t);
			new->entry = entry;
			new->value = strdupnull($3);
			new->next = NULL;
			if (_parser_kw_last)
				_parser_kw_last->next = new;
			_parser_kw_last = new;
			if (!*_parser_kw)
				*_parser_kw = new;
		}
		free($1);
		free($3);
	}
	| STRING EQUAL
	  {
		free($1);
	  }
	|
	;

%%

void yyerror(const char *s)
{
	if (_save_errors_)
		_parser_y_error(parser_errstring, ERRSTRING_LEN, s);
}

config_parsed_t *parser_load_conf(const char *file)
{
	config_parsed_t *cfg = NULL;
	int err = 0;
	FILE *f;

	extern void _parser_y_init(const char *f);
	extern void _parser_y_fini(void);
	extern FILE *yyin;

	memset(parser_errstring, 0, ERRSTRING_LEN+1);

	cfg = (config_parsed_t *)malloc_thing(config_parsed_t);
	if (cfg)
	{
		memset(cfg, 0, sizeof(config_parsed_t));
		f = fopen(file, "r");
		if (f)
		{
			yyin = f;
			_parser_y_init(file);
			_save_errors_ = 1;
			_parser_cfg = cfg;

			if (yyparse() !=0 )
			{
				if (parser_errstring[0] == '\0')
				{
					snprintf(parser_errstring, ERRSTRING_LEN, "Unknown error...");
				}
				_save_errors_ = 0;
				while (yyparse() != 0);
				err++;
			}
			else if (parser_errstring[0] != '\0')
			{
				err++;
			}
			else
			{
				/**
				 * Config valid
				 */
			}

			fclose(f);
		}
		else
		{
			snprintf(parser_errstring, ERRSTRING_LEN, "can't load file '%s'", file);
			err++;
		}
	}
	else
	{
		snprintf(parser_errstring, ERRSTRING_LEN, "can't allocate memory");
		err++;
	}

	if (err)
	{
		DBG1(DBG_APP, "%s", parser_errstring);

		if (cfg)
			parser_free_conf(cfg);
		cfg = NULL;
	}

	_parser_y_fini();
	return cfg;
}

static void parser_free_kwlist(kw_list_t *list)
{
	kw_list_t *elt;

	while (list)
	{
		elt = list;
		list = list->next;
		free(elt->value);
		free(elt);
	}
}

void parser_free_conf(config_parsed_t *cfg)
{
	section_list_t *sec;
	if (cfg)
	{
		parser_free_kwlist(cfg->config_setup);
		while (cfg->conn_first)
		{
			sec = cfg->conn_first;
			cfg->conn_first = cfg->conn_first->next;
			free(sec->name);
			parser_free_kwlist(sec->kw);
			free(sec);
		}
		while (cfg->ca_first)
		{
			sec = cfg->ca_first;
			cfg->ca_first = cfg->ca_first->next;
			free(sec->name);
			parser_free_kwlist(sec->kw);
			free(sec);
		}
		free(cfg);
	}
}
