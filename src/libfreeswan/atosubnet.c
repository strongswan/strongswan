/*
 * convert from ASCII form of subnet specification to binary
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

#ifndef DEFAULTSUBNET
#define	DEFAULTSUBNET	"%default"
#endif

/*
 - atosubnet - convert ASCII "addr/mask" to address and mask
 * Mask can be integer bit count.
 */
const char *			/* NULL for success, else string literal */
atosubnet(src, srclen, addrp, maskp)
const char *src;
size_t srclen;			/* 0 means "apply strlen" */
struct in_addr *addrp;
struct in_addr *maskp;
{
	const char *slash;
	const char *mask;
	size_t mlen;
	const char *oops;
	unsigned long bc;
	static char def[] = DEFAULTSUBNET;
#	define	DEFLEN	(sizeof(def) - 1)	/* -1 for NUL */
	static char defis[] = "0/0";
#	define	DEFILEN	(sizeof(defis) - 1)

	if (srclen == 0)
		srclen = strlen(src);
	if (srclen == 0)
		return "empty string";

	if (srclen == DEFLEN && strncmp(src, def, srclen) == 0) {
		src = defis;
		srclen = DEFILEN;
	}

	slash = memchr(src, '/', srclen);
	if (slash == NULL)
		return "no / in subnet specification";
	mask = slash + 1;
	mlen = srclen - (mask - src);

	oops = atoaddr(src, slash-src, addrp);
	if (oops != NULL)
		return oops;

	oops = atoul(mask, mlen, 10, &bc);
	if (oops == NULL) {
		/* atoul succeeded, it's a bit-count mask */
		if (bc > ABITS)
			return "bit-count mask too large";
#ifdef NOLEADINGZEROS
		if (mlen > 1 && *mask == '0')
			return "octal not allowed in mask";
#endif /* NOLEADINGZEROS */
		*maskp = bitstomask((int)bc);
	} else {
		oops = atoaddr(mask, mlen, maskp);
		if (oops != NULL)
			return oops;
		if (!goodmask(*maskp))
			return "non-contiguous mask";
	}

	addrp->s_addr &= maskp->s_addr;
	return NULL;
}



#ifdef ATOSUBNET_MAIN

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void regress(void);

int
main(int argc, char *argv[])
{
	struct in_addr a;
	struct in_addr m;
	char buf[100];
	const char *oops;
	size_t n;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s {addr/mask|-r}\n", argv[0]);
		exit(2);
	}

	if (strcmp(argv[1], "-r") == 0) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}

	oops = atosubnet(argv[1], 0, &a, &m);
	if (oops != NULL) {
		fprintf(stderr, "%s: conversion failed: %s\n", argv[0], oops);
		exit(1);
	}
	n = subnettoa(a, m, 0, buf, sizeof(buf));
	if (n > sizeof(buf)) {
		fprintf(stderr, "%s: reverse conversion of ", argv[0]);
		fprintf(stderr, "%s/", inet_ntoa(a));
		fprintf(stderr, "%s", inet_ntoa(m));
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
	{"1.2.3.0/255.255.255.0",	"1.2.3.0/24"},
	{"1.2.3.0/24",			"1.2.3.0/24"},
	{"1.2.3.1/255.255.255.240",	"1.2.3.0/28"},
	{"1.2.3.1/32",			"1.2.3.1/32"},
	{"1.2.3.1/0",			"0.0.0.0/0"},
/*	"1.2.3.1/255.255.127.0",	"1.2.3.0/255.255.127.0",	*/
	{"1.2.3.1/255.255.127.0",	NULL},
	{"128.009.000.032/32",		"128.9.0.32/32"},
	{"128.0x9.0.32/32",		NULL},
	{"0x80090020/32",		"128.9.0.32/32"},
	{"0x800x0020/32",		NULL},
	{"128.9.0.32/0xffFF0000",	"128.9.0.0/16"},
	{"128.9.0.32/0xff0000FF",	NULL},
	{"128.9.0.32/0x0000ffFF",	NULL},
	{"128.9.0.32/0x00ffFF0000",	NULL},
	{"128.9.0.32/0xffFF",		NULL},
	{"128.9.0.32.27/32",		NULL},
	{"128.9.0k32/32",		NULL},
	{"328.9.0.32/32",		NULL},
	{"128.9..32/32",		NULL},
	{"10/8",			"10.0.0.0/8"},
	{"10.0/8",			"10.0.0.0/8"},
	{"10.0.0/8",			"10.0.0.0/8"},
	{"10.0.1/24",			"10.0.1.0/24"},
	{"_",				NULL},
	{"_/_",				NULL},
	{"1.2.3.1",			NULL},
	{"1.2.3.1/_",			NULL},
	{"1.2.3.1/24._",		NULL},
	{"1.2.3.1/99",			NULL},
	{"localhost/32",		"127.0.0.1/32"},
	{"%default",			"0.0.0.0/0"},
	{NULL,				NULL}
};

void
regress()
{
	struct rtab *r;
	int status = 0;
	struct in_addr a;
	struct in_addr m;
	char in[100];
	char buf[100];
	const char *oops;
	size_t n;

	for (r = rtab; r->input != NULL; r++) {
		strcpy(in, r->input);
		oops = atosubnet(in, 0, &a, &m);
		if (oops != NULL && r->output == NULL)
			{}		/* okay, error expected */
		else if (oops != NULL) {
			printf("`%s' atosubnet failed: %s\n", r->input, oops);
			status = 1;
		} else if (r->output == NULL) {
			printf("`%s' atosubnet succeeded unexpectedly\n",
								r->input);
			status = 1;
		} else {
			n = subnettoa(a, m, 0, buf, sizeof(buf));
			if (n > sizeof(buf)) {
				printf("`%s' subnettoa failed:  need %ld\n",
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

#endif /* ATOSUBNET_MAIN */
