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
#include <errno.h>

#include <library.h>
#include <debug.h>
#include <utils/lexparser.h>

#include "optionsfrom.h"

#define	MAX_USES	 20		/* loop-detection limit */
#define	SOME_ARGS	 10		/* first guess at how many arguments we'll need */

/*
 * Defined in header.
 */
bool optionsfrom(const char *filename, int *argcp, char **argvp[], int optind)
{
	static int nuses = 0;
	char **newargv;
	int newargc;
	int next;			/* place for next argument */
	int room;			/* how many more new arguments we can hold */
	size_t bytes;
	chunk_t chunk, src, line, token;
	bool good = TRUE;
	int linepos = 0;
	FILE *fd;

	/* avoid endless loops with recursive --optionsfrom arguments */
	nuses++;
	if (nuses >= MAX_USES)
	{
		DBG1("optionsfrom called %d times - looping?", (*argvp)[0], nuses);
		return FALSE;
	}
	
	fd = fopen(filename, "r");
	if (fd == NULL)
	{
		DBG1("optionsfrom: unable to open file '%s': %s",
			 filename, strerror(errno));
		return FALSE;
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

	while (fetchline(&src, &line) && good)
	{
		linepos++;
		while (eat_whitespace(&line))
		{
			if (*line.ptr == '"'|| *line.ptr == '\'')
			{
				char delimiter = *line.ptr;

				line.ptr++;
				line.len--;
				if (!extract_token(&token, delimiter, &line))
				{
					DBG1("optionsfrom: missing terminator at %s:%d",
						 filename, linepos);
					good = FALSE;
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

	if (!good)		/* error of some kind */
	{
		free(chunk.ptr);
		free(newargv);
		return FALSE;
	}

	memcpy(newargv + next, *argvp + optind, (*argcp + 1 - optind) * sizeof(char *));
	*argcp += next - optind;
	*argvp = newargv;
	return TRUE;
}

