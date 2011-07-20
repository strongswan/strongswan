/* lexer (lexical analyzer) for control files
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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

#define MAX_TOK_LEN 2048    /* includes terminal '\0' */
struct file_lex_position
{
	int depth;  /* how deeply we are nested */
	const char *filename;
	FILE *fp;
	enum { B_none, B_record, B_file } bdry;     /* current boundary */
	int lino;   /* line number in file */
	char buffer[MAX_TOK_LEN + 1];    /* note: one extra char for our use (jamming '"') */
	char *cur;  /* cursor */
	char under; /* except in shift(): character originally at *cur */
	struct file_lex_position *previous;
};

extern struct file_lex_position *flp;

extern bool lexopen(struct file_lex_position *new_flp, const char *name, bool optional);
extern void lexclose(void);


/* Token decoding: shift() loads the next token into tok.
 * Iff a token starts at the left margin, it is considered
 * to be the first in a record.  We create a special condition,
 * Record Boundary (analogous to EOF), just before such a token.
 * We are unwilling to shift through a record boundary:
 * it must be overridden first.
 * Returns FALSE iff Record Boundary or EOF (i.e. no token);
 * tok will then be NULL.
 */

extern char *tok;
#define tokeq(s) (streq(tok, (s)))
#define tokeqword(s) (strcasecmp(tok, (s)) == 0)

extern bool shift(void);
extern bool flushline(const char *m);
