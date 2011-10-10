%option noinput
%option nounput
%{
/* FreeS/WAN config file parser (parser.l)
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

#include <string.h>
#include <stdlib.h>

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

#include "parser.h"

#define MAX_INCLUDE_DEPTH  20

extern void yyerror(const char *);
extern int yylex(void);
extern int yylex_destroy(void);

static struct {
	int stack_ptr;
	YY_BUFFER_STATE stack[MAX_INCLUDE_DEPTH];
	FILE *file[MAX_INCLUDE_DEPTH];
	unsigned int line[MAX_INCLUDE_DEPTH];
	char *filename[MAX_INCLUDE_DEPTH];
} __parser_y_private;

void _parser_y_error(char *b, int size, const char *s);
void _parser_y_init (const char *f);
void _parser_y_fini (void);
int _parser_y_include (const char *filename);

void _parser_y_error(char *b, int size, const char *s)
{
	extern char *yytext; // was: char yytext[];

	snprintf(b, size, "%s:%d: %s [%s]",
			__parser_y_private.filename[__parser_y_private.stack_ptr],
			__parser_y_private.line[__parser_y_private.stack_ptr],
			s, yytext);
}

void _parser_y_init (const char *f)
{
	memset(&__parser_y_private, 0, sizeof(__parser_y_private));
	__parser_y_private.line[0] = 1;
	__parser_y_private.filename[0] = strdup(f);
}

void _parser_y_fini (void)
{
	unsigned int i;

	for (i = 0; i < MAX_INCLUDE_DEPTH; i++)
	{
		if (__parser_y_private.filename[i])
			free(__parser_y_private.filename[i]);
		if (__parser_y_private.file[i])
			fclose(__parser_y_private.file[i]);
	}
	memset(&__parser_y_private, 0, sizeof(__parser_y_private));
	yylex_destroy();
}

/**
 * parse the file located at filename
 */
int include_file(char *filename)
{
	unsigned int p = __parser_y_private.stack_ptr + 1;
	FILE *f;

	if (p >= MAX_INCLUDE_DEPTH)
	{
		yyerror("max inclusion depth reached");
		return 1;
	}

	f = fopen(filename, "r");
	if (!f)
	{
		yyerror("can't open include filename");
		return 0; /* ignore this error */
	}

	__parser_y_private.stack_ptr++;
	__parser_y_private.file[p] = f;
	__parser_y_private.stack[p] = YY_CURRENT_BUFFER;
	__parser_y_private.line[p] = 1;
	__parser_y_private.filename[p] = strdup(filename);

	yy_switch_to_buffer(yy_create_buffer(f, YY_BUF_SIZE));
	return 0;
}

int _parser_y_include (const char *filename)
{
	int ret = 0;
#ifdef HAVE_GLOB_H
	{
		glob_t files;
		int i;

		ret = glob(filename, GLOB_ERR, NULL, &files);
		if (ret)
		{
			const char *err;

			switch (ret)
			{
				case GLOB_NOSPACE:
					err = "include files ran out of memory";
					break;
				case GLOB_ABORTED:
					err = "include files aborted due to read error";
					break;
				case GLOB_NOMATCH:
					err = "include files found no matches";
					break;
				default:
					err = "unknown include files error";
			}
			globfree(&files);
			yyerror(err);
			return 1;
		}

		for (i = 0; i < files.gl_pathc; i++)
		{
			if ((ret = include_file(files.gl_pathv[i])))
			{
				break;
			}
		}
		globfree(&files);
	}
#else /* HAVE_GLOB_H */
	/* if glob(3) is not available, try to load pattern directly */
	ret = include_file(filename);
#endif /* HAVE_GLOB_H */
	return ret;
}

%}

%%

<<EOF>> {
		if (__parser_y_private.filename[__parser_y_private.stack_ptr]) {
				free(__parser_y_private.filename[__parser_y_private.stack_ptr]);
				__parser_y_private.filename[__parser_y_private.stack_ptr] = NULL;
		}
		if (__parser_y_private.file[__parser_y_private.stack_ptr]) {
				fclose(__parser_y_private.file[__parser_y_private.stack_ptr]);
				__parser_y_private.file[__parser_y_private.stack_ptr] = NULL;
				yy_delete_buffer (YY_CURRENT_BUFFER);
				yy_switch_to_buffer
						(__parser_y_private.stack[__parser_y_private.stack_ptr]);
		}
		if (--__parser_y_private.stack_ptr < 0) {
				yyterminate();
		}
}

^[\t ]+                 return FIRST_SPACES;

[\t ]+                  /* ignore spaces in line */ ;

=                               return EQUAL;

\n|#.*\n                {
										__parser_y_private.line[__parser_y_private.stack_ptr]++;
										return EOL;
								}

config                  return CONFIG;
setup                   return SETUP;
conn                    return CONN;
ca                      return CA;
include                 return INCLUDE;
version                 return FILE_VERSION;

[^\"= \t\n]+    {
										yylval.s = strdup(yytext);
										return STRING;
								}

\"[^\"\n]*\"    {
										yylval.s = strdup(yytext+1);
										if (yylval.s) yylval.s[strlen(yylval.s)-1]='\0';
										return STRING;
								}

.                               yyerror(yytext);

%%

int yywrap(void)
{
	return 1;
}

