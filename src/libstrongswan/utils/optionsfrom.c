/**
 * @file optionsfrom.c
 * 
 * @brief read command line options from a file
 * 
 */

/*
 * Copyright (C) 1998, 1999  Henry Spencer.
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 * 
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#include <stdio.h>

#include <library.h>
#include <utils/lexparser.h>

#include "optionsfrom.h"

#define	MAX_USES	100		/* loop-detection limit */
#define	SOME_ARGS	 10		/* first guess at how many arguments we'll need */

/**
 * parse the options from a file
 * does not alter the existing arguments, but does relocate and alter
 * the argv pointer vector.
 */
static err_t parse_options_file(const char *filename, int *argcp, char **argvp[], int optind)
{
	char **newargv;
	int newargc;
	int next;			/* place for next argument */
	int room;			/* how many more new arguments we can hold */
	size_t bytes;
	chunk_t chunk, src, line, token;
	err_t ugh = NULL;

	FILE *fd = fopen(filename, "r");

	if (fd == NULL)
	{
		return "unable to open file";
	}

	/* determine the file size */
	fseek(fd, 0, SEEK_END);
	chunk.len = ftell(fd);
	rewind(fd);

	/* allocate one byte more just in case of a missing final newline */
	chunk.ptr = malloc(chunk.len + 1);

	/* read the whole file into a chunk */
	bytes = fread(chunk.ptr, 1, chunk.len, fd);
	fclose(fd);

	newargc = *argcp + SOME_ARGS;
	newargv = malloc((newargc + 1) * sizeof(char *));
	memcpy(newargv, *argvp, optind * sizeof(char *));
	room = SOME_ARGS;
	next = optind;
	newargv[next] = NULL;

	/* we keep the chunk pointer so that we can still free it */
	src = chunk;

	while (fetchline(&src, &line) && ugh == NULL)
	{
		while (eat_whitespace(&line))
		{
			if (*line.ptr == '"'|| *line.ptr == '\'')
			{
				char delimiter = *line.ptr;

				line.ptr++;
				line.len--;
				if (!extract_token(&token, delimiter, &line))
				{
					ugh = "missing terminating delimiter";
					break;
				}
			}
			else
			{
				if (!extract_token(&token, ' ', &line))
				{
					/* last token in a line */
					token = line;
					line.len = 0;
				}
			}

			/* do we have to allocate more memory for additional arguments? */
			if (room == 0)
			{
				newargc += SOME_ARGS;
				newargv = realloc(newargv, (newargc+1) * sizeof(char *));
				room = SOME_ARGS;
			}

			/* terminate the token by replacing the delimiter with a null character */
			*(token.ptr + token.len) = '\0';

			/* assign the token to the next argument */
			newargv[next] = token.ptr;
			next++;
			room--;
		}
	}

	if (ugh)		/* error of some kind */
	{
		free(chunk.ptr);
		free(newargv);
		return ugh;
	}

	memcpy(newargv + next, *argvp + optind, (*argcp + 1 - optind) * sizeof(char *));
	*argcp += next - optind;
	*argvp = newargv;
	return NULL;
}

/*
 * Defined in header.
 */
err_t optionsfrom(const char *filename, int *argcp, char **argvp[], int optind, FILE *errfile)
{
	static int nuses = 0;
	err_t ugh = NULL;

	/* avoid endless loops with recursive --optionsfrom arguments */
	if (errfile != NULL)
	{
		nuses++;
		if (nuses >= MAX_USES)
		{
			fprintf(errfile, "%s: optionsfrom called %d times - looping?\n",
							 (*argvp)[0], nuses);
			exit(2);
		}
	}
	else
	{
		nuses = 0;
	}

	ugh = parse_options_file(filename, argcp, argvp, optind);

	if (ugh != NULL && errfile != NULL)
	{
		fprintf(errfile, "%s: optionsfrom failed: %s\n", (*argvp)[0], ugh);
		exit(2);
	}
	return ugh;
}
