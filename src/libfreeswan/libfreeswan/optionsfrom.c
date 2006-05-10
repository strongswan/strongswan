/*
 * pick up more options from a file, in the middle of an option scan
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
 * RCSID $Id: optionsfrom.c,v 1.1 2004/03/15 20:35:26 as Exp $
 */
#include "internal.h"
#include "freeswan.h"

#include <stdio.h>

#define	MAX	100		/* loop-detection limit */

/* internal work area */
struct work {
#	define	LOTS	1024
	char buf[LOTS];
	char *line;
	char *pending;
};

static const char *dowork(const char *, int *, char ***, int);
static const char *getanarg(FILE *, struct work *, char **);
static char *getline(FILE *, char *, size_t);

/*
 - optionsfrom - add some options, taken from a file, to argc/argv
 * If errsto is non-NULL, does not return in event of error.
 */
const char *			/* NULL for success, else string literal */
optionsfrom(filename, argcp, argvp, optind, errsto)
const char *filename;
int *argcp;			/* pointer to argc */
char ***argvp;			/* pointer to argv */
int optind;			/* current optind, number of next argument */
FILE *errsto;			/* where to report errors (NULL means return) */
{
	const char *e;
	static int nuses = 0;

	if (errsto != NULL) {
		nuses++;
		if (nuses >= MAX) {
			fprintf(errsto,
				"%s: optionsfrom called %d times, looping?\n",
				(*argvp)[0], nuses);
			exit(2);
		}
	} else
		nuses = 0;

	e = dowork(filename, argcp, argvp, optind);
	if (e != NULL && errsto != NULL) {
		fprintf(errsto, "%s: optionsfrom failed: %s\n", (*argvp)[0], e);
		exit(2);
	}
	return e;
}

/*
 - dowork - do all the real work of optionsfrom
 * Does not alter the existing arguments, but does relocate and alter
 * the argv pointer vector.
 */
static const char *		/* NULL for success, else string literal */
dowork(filename, argcp, argvp, optind)
const char *filename;
int *argcp;			/* pointer to argc */
char ***argvp;			/* pointer to argv */
int optind;			/* current optind, number of next argument */
{
	char **newargv;
	char **tmp;
	int newargc;
	int next;		/* place for next argument */
	int room;		/* how many more new arguments we can hold */
#	define	SOME	10	/* first guess at how many we'll need */
	FILE *f;
	int i;
	const char *p;
	struct work wa;		/* for getanarg() */

	f = fopen(filename, "r");
	if (f == NULL)
		return "unable to open file";

	newargc = *argcp + SOME;
	newargv = malloc((newargc+1) * sizeof(char *));
	if (newargv == NULL)
		return "unable to allocate memory";
	memcpy(newargv, *argvp, optind * sizeof(char *));
	room = SOME;
	next = optind;

	newargv[next] = NULL;
	wa.pending = NULL;
	while ((p = getanarg(f, &wa, &newargv[next])) == NULL) {
		if (room == 0) {
			newargc += SOME;
			tmp = realloc(newargv, (newargc+1) * sizeof(char *));
			if (tmp == NULL) {
				p = "out of space for new argv";
				break;		/* NOTE BREAK OUT */
			}
			newargv = tmp;
			room += SOME;
		}
		next++;
		room--;
	}
	if (p != NULL && !feof(f)) {	/* error of some kind */
		for (i = optind+1; i <= next; i++)
			if (newargv[i] != NULL)
				free(newargv[i]);
		free(newargv);
		fclose(f);
		return p;
	}

	fclose(f);
	memcpy(newargv + next, *argvp + optind,
					(*argcp+1-optind) * sizeof(char *));
	*argcp += next - optind;
	*argvp = newargv;
	return NULL;
}

/*
 - getanarg - get a malloced argument from the file
 */
static const char *		/* NULL for success, else string literal */
getanarg(f, w, linep)
FILE *f;
struct work *w;
char **linep;			/* where to store pointer if successful */
{
	size_t len;
	char *p;
	char *endp;

	while (w->pending == NULL) {	/* no pending line */
		if ((w->line = getline(f, w->buf, sizeof(w->buf))) == NULL)
			return "error in line read";	/* caller checks EOF */
		if (w->line[0] != '#' &&
				*(w->line + strspn(w->line, " \t")) != '\0')
			w->pending = w->line;
	}

	if (w->pending == w->line && w->line[0] != '-') {
		/* fresh plain line */
		w->pending = NULL;
		p = w->line;
		endp = p + strlen(p);
		if (*p == '"' && endp > p+1 && *(endp-1) == '"') {
			p++;
			endp--;
			*endp = '\0';
		}
		if (w->line == w->buf) {
			*linep = malloc(endp - p + 1);
			if (*linep == NULL)
				return "out of memory for new line";
			strcpy(*linep, p);
		} else			/* getline already malloced it */
			*linep = p;
		return NULL;
	}

	/* chip off a piece of a pending line */
	p = w->pending;
	p += strspn(p, " \t");
	endp = p + strcspn(p, " \t");
	len = endp - p;
	if (*endp != '\0') {
		*endp++ = '\0';
		endp += strspn(endp, " \t");
	}
	/* endp now points to next real character, or to line-end NUL */
	*linep = malloc(len + 1);
	if (*linep == NULL) {
		if (w->line != w->buf)
			free(w->line);
		return "out of memory for new argument";
	}
	strcpy(*linep, p);
	if (*endp == '\0') {
		w->pending = NULL;
		if (w->line != w->buf)
			free(w->line);
	} else
		w->pending = endp;
	return NULL;
}

/*
 - getline - read a line from the file, trim newline off
 */
static char *			/* pointer to line, NULL for eof/error */
getline(f, buf, bufsize)
FILE *f;
char *buf;			/* buffer to use, if convenient */
size_t bufsize;			/* size of buf */
{
	size_t len;

	if (fgets(buf, bufsize, f) == NULL)
		return NULL;
	len = strlen(buf);

	if (len < bufsize-1 || buf[bufsize-1] == '\n') {
		/* it fit */
		buf[len-1] = '\0';
		return buf;
	}

	/* oh crud, buffer overflow */
	/* for now, to hell with it */
	return NULL;
}



#ifdef TEST

#include <getopt.h>

char usage[] = "Usage: tester [--foo] [--bar] [--optionsfrom file] arg ...";
struct option opts[] = {
	"foo",		0,	NULL,	'f',
	"bar",		0,	NULL,	'b',
	"builtin",	0,	NULL,	'B',
	"optionsfrom",	1,	NULL,	'+',
	"help",		0,	NULL,	'h',
	"version",	0,	NULL,	'v',
	0,		0,	NULL,	0,
};

int
main(argc, argv)
int argc;
char *argv[];
{
	int opt;
	extern char *optarg;
	extern int optind;
	int errflg = 0;
	const char *p;
	int i;
	FILE *errs = NULL;

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != EOF)
		switch (opt) {
		case 'f':
		case 'b':
			break;
		case 'B':
			errs = stderr;
			break;
		case '+':	/* optionsfrom */
			p = optionsfrom(optarg, &argc, &argv, optind, errs);
			if (p != NULL) {
				fprintf(stderr, "%s: optionsfrom error: %s\n",
								argv[0], p);
				exit(1);
			}
			break;
		case 'h':	/* help */
			printf("%s\n", usage);
			exit(0);
			break;
		case 'v':	/* version */
			printf("1\n");
			exit(0);
			break;
		case '?':
		default:
			errflg = 1;
			break;
		}
	if (errflg) {
		fprintf(stderr, "%s\n", usage);
		exit(2);
	}

	for (i = 1; i < argc; i++)
		printf("%d: `%s'\n", i, argv[i]);
	exit(0);
}


#endif /* TEST */
