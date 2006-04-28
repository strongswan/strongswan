/*
 * random bit generation for scripts, control files, etc.
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
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
 * RCSID $Id: ranbits.c,v 1.1 2004/03/15 20:35:30 as Exp $
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <freeswan.h>

#ifndef DEVICE
#define	DEVICE	"/dev/random"
#endif
#ifndef QDEVICE
#define	QDEVICE	"/dev/urandom"
#endif
#ifndef MAXBITS
#define	MAXBITS	20000
#endif

char usage[] = "Usage: ranbits [--quick] [--continuous] [--bytes] nbits";
struct option opts[] = {
  {"quick",	0,	NULL,	'q',},
  {"continuous",	0,	NULL,	'c',},
  {"bytes",	0,	NULL,	'b',},
  {"help",		0,	NULL,	'h',},
  {"version",	0,	NULL,	'v',},
  {0,		0,	NULL,	0,}
};
int quick = 0;			/* quick and dirty? */
char format = 'h';		/* datatot() format code */
int isbytes = 0;		/* byte count rather than bits? */

char me[] = "ipsec ranbits";	/* for messages */

char buf[MAXBITS/CHAR_BIT];
char outbuf[3*sizeof(buf)];

int main(int argc, char *argv[])
{
	int opt;
	extern int optind;
	int errflg = 0;
	int nbits;
	size_t nbytes;
	char *devname;
	int dev;
	size_t ndone;
	size_t nneeded;
	ssize_t got;

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != EOF)
		switch (opt) {
		case 'q':	/* quick and dirty randomness */
			quick = 1;
			break;
		case 'c':	/* continuous hex, no underscores */
			format = 'x';
			break;
		case 'b':	/* byte count, not bit count */
			isbytes = 1;
			break;
		case 'h':	/* help */
			printf("%s\n", usage);
			exit(0);
			break;
		case 'v':	/* version */
			printf("%s %s\n", me, ipsec_version_code());
			exit(0);
			break;
		case '?':
		default:
			errflg = 1;
			break;
		}
	if (errflg || optind != argc-1) {
		fprintf(stderr, "%s\n", usage);
		exit(2);
	}

	nbits = atoi(argv[optind]);
	if (isbytes)
		nbits *= CHAR_BIT;
	if (nbits <= 0) {
		fprintf(stderr, "%s: invalid bit count (%d)\n", me, nbits);
		exit(1);
	}
	if (nbits > MAXBITS) {
		fprintf(stderr, "%s: overlarge bit count (max %d)\n", me,
								MAXBITS);
		exit(1);
	}
	nbytes = (size_t)(nbits + CHAR_BIT - 1) / CHAR_BIT;

	devname = (quick) ? QDEVICE : DEVICE;
	dev = open(devname, 0);
	if (dev < 0) {
		fprintf(stderr, "%s: could not open %s (%s)\n", me,
						devname, strerror(errno));
		exit(1);
	}

	ndone = 0;
	while (ndone < nbytes) {
		got = read(dev, buf + ndone, nbytes - ndone);
		if (got < 0) {
			fprintf(stderr, "%s: read error on %s (%s)\n", me,
						devname, strerror(errno));
			exit(1);
		}
		if (got == 0) {
			fprintf(stderr, "%s: eof on %s!?!\n", me, devname);
			exit(1);
		}
		ndone += got;
	}

	nneeded = datatot(buf, nbytes, format, outbuf, sizeof(outbuf));
	if (nneeded > sizeof(outbuf)) {
		fprintf(stderr, "%s: buffer overflow (need %ld bytes)?!?\n",
						me, (long)nneeded);
		exit(1);
	}
	printf("%s\n", outbuf);
	exit(0);
}
