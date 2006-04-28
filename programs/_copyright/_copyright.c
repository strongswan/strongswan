/*
 * copyright reporter
 * (just avoids having the info in more than one place in the source)
 * Copyright (C) 2001  Henry Spencer.
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
 * RCSID $Id: _copyright.c,v 1.1 2004/03/15 20:35:27 as Exp $
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <freeswan.h>

char usage[] = "Usage: ipsec _copyright";
struct option opts[] = {
  {"help",	0,	NULL,	'h',},
  {"version",	0,	NULL,	'v',},
  {0,		0,	NULL,	0, },
};

char me[] = "ipsec _copyright";	/* for messages */

int
main(int argc, char *argv[])
{
	int opt;
	extern int optind;
	int errflg = 0;
	const char *version = ipsec_version_code();
	const char **notice = ipsec_copyright_notice();
	const char **co;

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != EOF)
		switch (opt) {
		case 'h':	/* help */
			printf("%s\n", usage);
			exit(0);
			break;
		case 'v':	/* version */
			printf("%s %s\n", me, version);
			exit(0);
			break;
		case '?':
		default:
			errflg = 1;
			break;
		}
	if (errflg || optind != argc) {
		fprintf(stderr, "%s\n", usage);
		exit(2);
	}

	for (co = notice; *co != NULL; co++)
		printf("%s\n", *co);
	exit(0);
}
