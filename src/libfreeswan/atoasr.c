/*
 * convert from ASCII form of address/subnet/range to binary
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
 */
#include "internal.h"
#include "freeswan.h"

/*
 - atoasr - convert ASCII to address, subnet, or range
 */
const char *			/* NULL for success, else string literal */
atoasr(src, srclen, typep, addrsp)
const char *src;
size_t srclen;			/* 0 means "apply strlen" */
char *typep;			/* return type code:  'a', 's', 'r' */
struct in_addr addrsp[2];
{
	const char *punct;
	const char *stop;
	const char *oops;

	if (srclen == 0)
		srclen = strlen(src);
	if (srclen == 0)
		return "empty string";

	/* subnet is easy to spot */
	punct = memchr(src, '/', srclen);
	if (punct != NULL) {
		*typep = 's';
		return atosubnet(src, srclen, &addrsp[0], &addrsp[1]);
	}

	/* try for a range */
	stop = src + srclen;
	for (punct = src; (punct = memchr(punct, '.', stop - punct)) != NULL;
									punct++)
		if (stop - punct > 3 && *(punct+1) == '.' && *(punct+2) == '.')
			break;			/* NOTE BREAK OUT */
	if (punct == NULL) {
		/* didn't find the range delimiter, must be plain address */
		*typep = 'a';
		return atoaddr(src, srclen, &addrsp[0]);
	}

	/* looks like a range */
	*typep = 'r';
	if (stop - punct > 4 && *(punct+3) == '.')
		punct++;		/* first dot is trailing dot of name */
	oops = atoaddr(src, punct - src, &addrsp[0]);
	if (oops != NULL)
		return oops;
	oops = atoaddr(punct+3, stop - (punct+3), &addrsp[1]);
	if (oops != NULL)
		return oops;
	if (ntohl(addrsp[0].s_addr) > ntohl(addrsp[1].s_addr))
		return "invalid range, begin > end";
	return NULL;
}



#ifdef ATOASR_MAIN

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void regress(void);

int
main(int argc, char *argv[])
{
	struct in_addr a[2];
	char buf[100];
	const char *oops;
	size_t n;
	char type;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s {addr|net/mask|begin...end|-r}\n",
								argv[0]);
		exit(2);
	}

	if (strcmp(argv[1], "-r") == 0) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}

	oops = atoasr(argv[1], 0, &type, a);
	if (oops != NULL) {
		fprintf(stderr, "%s: conversion failed: %s\n", argv[0], oops);
		exit(1);
	}
	switch (type) {
	case 'a':
		n = addrtoa(a[0], 0, buf, sizeof(buf));
		break;
	case 's':
		n = subnettoa(a[0], a[1], 0, buf, sizeof(buf));
		break;
	case 'r':
		n = rangetoa(a, 0, buf, sizeof(buf));
		break;
	default:
		fprintf(stderr, "%s: unknown type '%c'\n", argv[0], type);
		exit(1);
		break;
	}
	if (n > sizeof(buf)) {
		fprintf(stderr, "%s: reverse conversion of ", argv[0]);
		fprintf(stderr, "%s ", inet_ntoa(a[0]));
		fprintf(stderr, "%s", inet_ntoa(a[1]));
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
	{"1.2.3.0",			"1.2.3.0"},
	{"1.2.3.0/255.255.255.0",	"1.2.3.0/24"},
	{"1.2.3.0...1.2.3.5",		"1.2.3.0...1.2.3.5"},
	{"1.2.3.4.5",			NULL},
	{"1.2.3.4/",			NULL},
	{"1.2.3.4...",			NULL},
	{"1.2.3.4....",			NULL},
	{"localhost/32",		        "127.0.0.1/32"},
	{"localhost...127.0.0.3",	"127.0.0.1...127.0.0.3"},
	{"127.0.0.0...localhost",	"127.0.0.0...127.0.0.1"},
	{"127.0.0.3...localhost",	NULL},
	{NULL,				NULL}
};

void
regress(void)
{
	struct rtab *r;
	int status = 0;
	struct in_addr a[2];
	char in[100];
	char buf[100];
	const char *oops;
	size_t n;
	char type;

	for (r = rtab; r->input != NULL; r++) {
		strcpy(in, r->input);
		oops = atoasr(in, 0, &type, a);
		if (oops != NULL && r->output == NULL)
			{}		/* okay, error expected */
		else if (oops != NULL) {
			printf("`%s' atoasr failed: %s\n", r->input, oops);
			status = 1;
		} else if (r->output == NULL) {
			printf("`%s' atoasr succeeded unexpectedly '%c'\n",
							r->input, type);
			status = 1;
		} else {
			switch (type) {
			case 'a':
				n = addrtoa(a[0], 0, buf, sizeof(buf));
				break;
			case 's':
				n = subnettoa(a[0], a[1], 0, buf, sizeof(buf));
				break;
			case 'r':
				n = rangetoa(a, 0, buf, sizeof(buf));
				break;
			default:
				fprintf(stderr, "`%s' unknown type '%c'\n",
							r->input, type);
				n = 0;
				status = 1;
				break;
			}
			if (n > sizeof(buf)) {
				printf("`%s' '%c' reverse failed:  need %ld\n",
						r->input, type, (long)n);
				status = 1;
			} else if (n > 0 && strcmp(r->output, buf) != 0) {
				printf("`%s' '%c' gave `%s', expected `%s'\n",
					r->input, type, buf, r->output);
				status = 1;
			}
		}
	}
	exit(status);
}

#endif /* ATOASR_MAIN */
