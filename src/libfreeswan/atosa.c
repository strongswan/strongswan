/*
 * convert from ASCII form of SA ID to binary
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
 * RCSID $Id: atosa.c,v 1.1 2004/03/15 20:35:26 as Exp $
 */
#include "internal.h"
#include "freeswan.h"

static struct satype {
	char *prefix;
	size_t prelen;		/* strlen(prefix) */
	int proto;
} satypes[] = {
	{ "ah",		2,	SA_AH	},
	{ "esp",	3,	SA_ESP	},
	{ "tun",	3,	SA_IPIP },
	{ "comp",	4,	SA_COMP },
	{ NULL,		0,	0,	}
};

/*
 - atosa - convert ASCII "ah507@10.0.0.1" to SA identifier
 */
const char *			/* NULL for success, else string literal */
atosa(src, srclen, sa)
const char *src;
size_t srclen;			/* 0 means "apply strlen" */
struct sa_id *sa;
{
	const char *at;
	const char *addr;
	const char *spi = NULL;
	struct satype *sat;
	unsigned long ul;
	const char *oops;
#	define	MINLEN	5	/* ah0@0 is as short as it can get */
	static char ptname[] = PASSTHROUGHNAME;
#	define	PTNLEN	(sizeof(ptname)-1)	/* -1 for NUL */

	if (srclen == 0)
		srclen = strlen(src);
	if (srclen == 0)
		return "empty string";
	if (srclen < MINLEN)
		return "string too short to be SA specifier";
	if (srclen == PTNLEN && memcmp(src, ptname, PTNLEN) == 0) {
		src = PASSTHROUGHIS;
		srclen = strlen(src);
	}

	at = memchr(src, '@', srclen);
	if (at == NULL)
		return "no @ in SA specifier";

	for (sat = satypes; sat->prefix != NULL; sat++)
		if (sat->prelen < srclen &&
				strncmp(src, sat->prefix, sat->prelen) == 0) {
			sa->proto = sat->proto;
			spi = src + sat->prelen;
			break;			/* NOTE BREAK OUT */
		}
	if (sat->prefix == NULL)
		return "SA specifier lacks valid protocol prefix";

	if (spi >= at)
		return "no SPI in SA specifier";
	oops = atoul(spi, at - spi, 13, &ul);
	if (oops != NULL)
		return oops;
	sa->spi = htonl(ul);

	addr = at + 1;
	oops = atoaddr(addr, srclen - (addr - src), &sa->dst);
	if (oops != NULL)
		return oops;

	return NULL;
}



#ifdef ATOSA_MAIN

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void regress(void);

int
main(int argc, char *argv[])
{
	struct sa_id sa;
	char buf[100];
	const char *oops;
	size_t n;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s {ahnnn@aaa|-r}\n", argv[0]);
		exit(2);
	}

	if (strcmp(argv[1], "-r") == 0) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}

	oops = atosa(argv[1], 0, &sa);
	if (oops != NULL) {
		fprintf(stderr, "%s: conversion failed: %s\n", argv[0], oops);
		exit(1);
	}
	n = satoa(sa, 0, buf, sizeof(buf));
	if (n > sizeof(buf)) {
		fprintf(stderr, "%s: reverse conv of `%d'", argv[0], sa.proto);
		fprintf(stderr, "%lu@", (long unsigned int)sa.spi);
		fprintf(stderr, "%s", inet_ntoa(sa.dst));
		fprintf(stderr, " failed: need %ld bytes, have only %ld\n",
						(long)n, (long)sizeof(buf));
		exit(1);
	}
	printf("%s\n", buf);

	exit(0);
}

struct rtab {
	char *input;
	char *output;			/* NULL means error expected */
} rtab[] = {
	{"esp257@1.2.3.0",		"esp257@1.2.3.0"},
	{"ah0x20@1.2.3.4",		"ah32@1.2.3.4"},
	{"tun011@111.2.3.99",		"tun11@111.2.3.99"},
	{"",				NULL},
	{"_",				NULL},
	{"ah2.2",			NULL},
	{"goo2@1.2.3.4",			NULL},
	{"esp9@1.2.3.4",			"esp9@1.2.3.4"},
	{"espp9@1.2.3.4",		NULL},
	{"es9@1.2.3.4",			NULL},
	{"ah@1.2.3.4",			NULL},
	{"esp7x7@1.2.3.4",		NULL},
	{"esp77@1.0x2.3.4",		NULL},
	{PASSTHROUGHNAME,		PASSTHROUGHNAME},
        {NULL,				NULL}
};

void
regress(void)
{
	struct rtab *r;
	int status = 0;
	struct sa_id sa;
	char in[100];
	char buf[100];
	const char *oops;
	size_t n;

	for (r = rtab; r->input != NULL; r++) {
		strcpy(in, r->input);
		oops = atosa(in, 0, &sa);
		if (oops != NULL && r->output == NULL)
			{}		/* okay, error expected */
		else if (oops != NULL) {
			printf("`%s' atosa failed: %s\n", r->input, oops);
			status = 1;
		} else if (r->output == NULL) {
			printf("`%s' atosa succeeded unexpectedly\n",
								r->input);
			status = 1;
		} else {
			n = satoa(sa, 'd', buf, sizeof(buf));
			if (n > sizeof(buf)) {
				printf("`%s' satoa failed:  need %ld\n",
							r->input, (long)n);
				status = 1;
			} else if (strcmp(r->output, buf) != 0) {
				printf("`%s' gave `%s', expected `%s'\n",
						r->input, buf, r->output);
				status = 1;
			}
		}
	}
	exit(status);
}

#endif /* ATOSA_MAIN */
