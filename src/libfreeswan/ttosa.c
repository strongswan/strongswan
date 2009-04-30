/*
 * convert from text form of SA ID to binary
 * Copyright (C) 2000, 2001  Henry Spencer.
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
#include <sys/socket.h>

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
	{ "comp",	4,	SA_COMP	},
	{ "int",	3,	SA_INT	},
	{ NULL,		0,	0,	}
};

static struct magic {
	char *name;
	char *really;
} magic[] = {
	{ PASSTHROUGHNAME,	PASSTHROUGH4IS		},
	{ PASSTHROUGH4NAME,	PASSTHROUGH4IS		},
	{ PASSTHROUGH6NAME,	PASSTHROUGH6IS		},
	{ "%pass",		"int256@0.0.0.0"	},
	{ "%drop",		"int257@0.0.0.0"	},
	{ "%reject",		"int258@0.0.0.0"	},
	{ "%hold",		"int259@0.0.0.0"	},
	{ "%trap",		"int260@0.0.0.0"	},
	{ "%trapsubnet",	"int261@0.0.0.0"	},
	{ NULL,			NULL			}
};

/*
 - ttosa - convert text "ah507@10.0.0.1" to SA identifier
 */
err_t				/* NULL for success, else string literal */
ttosa(src, srclen, sa)
const char *src;
size_t srclen;			/* 0 means "apply strlen" */
ip_said *sa;
{
	const char *at;
	const char *addr;
	size_t alen;
	const char *spi = NULL;
	struct satype *sat;
	unsigned long ul;
	const char *oops;
	struct magic *mp;
	size_t nlen;
#	define	MINLEN	5	/* ah0@0 is as short as it can get */
	int af;
	int base;

	if (srclen == 0)
		srclen = strlen(src);
	if (srclen == 0)
		return "empty string";
	if (srclen < MINLEN)
		return "string too short to be SA identifier";
	if (*src == '%') {
		for (mp = magic; mp->name != NULL; mp++) {
			nlen = strlen(mp->name);
			if (srclen == nlen && memcmp(src, mp->name, nlen) == 0)
				break;
		}
		if (mp->name == NULL)
			return "unknown % keyword";
		src = mp->really;
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
	switch (*spi) {
	case '.':
		af = AF_INET;
		spi++;
		base = 16;
		break;
	case ':':
		af = AF_INET6;
		spi++;
		base = 16;
		break;
	default:
		af = AF_UNSPEC;		/* not known yet */
		base = 0;
		break;
	}
	if (spi >= at)
		return "no SPI found in SA specifier";
	oops = ttoul(spi, at - spi, base, &ul);
	if (oops != NULL)
		return oops;
	sa->spi = htonl(ul);

	addr = at + 1;
	alen = srclen - (addr - src);
	if (af == AF_UNSPEC)
		af = (memchr(addr, ':', alen) != NULL) ? AF_INET6 : AF_INET;
	oops = ttoaddr(addr, alen, af, &sa->dst);
	if (oops != NULL)
		return oops;

	return NULL;
}



#ifdef TTOSA_MAIN

#include <stdio.h>

void regress(void);

int
main(int argc, char *argv[])
{
	ip_said sa;
	char buf[100];
	char buf2[100];
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

	oops = ttosa(argv[1], 0, &sa);
	if (oops != NULL) {
		fprintf(stderr, "%s: conversion failed: %s\n", argv[0], oops);
		exit(1);
	}
	n = satot(&sa, 0, buf, sizeof(buf));
	if (n > sizeof(buf)) {
		fprintf(stderr, "%s: reverse conv of `%d'", argv[0], sa.proto);
		fprintf(stderr, "%lx@", (long unsigned int)sa.spi);
		(void) addrtot(&sa.dst, 0, buf2, sizeof(buf2));
		fprintf(stderr, "%s", buf2);
		fprintf(stderr, " failed: need %ld bytes, have only %ld\n",
						(long)n, (long)sizeof(buf));
		exit(1);
	}
	printf("%s\n", buf);

	exit(0);
}

struct rtab {
	int format;
#		define	FUDGE	0x1000
	char *input;
	char *output;			/* NULL means error expected */
} rtab[] = {
	{0, "esp257@1.2.3.0",		"esp.101@1.2.3.0"},
	{0, "ah0x20@1.2.3.4",		"ah.20@1.2.3.4"},
	{0, "tun20@1.2.3.4",		"tun.14@1.2.3.4"},
	{0, "comp20@1.2.3.4",		"comp.14@1.2.3.4"},
	{0, "esp257@::1",		"esp:101@::1"},
	{0, "esp257@0bc:12de::1",	"esp:101@bc:12de::1"},
	{0, "esp78@1049:1::8007:2040",	"esp:4e@1049:1::8007:2040"},
	{0, "esp0x78@1049:1::8007:2040",	"esp:78@1049:1::8007:2040"},
	{0, "ah78@1049:1::8007:2040",	"ah:4e@1049:1::8007:2040"},
	{0, "ah0x78@1049:1::8007:2040",	"ah:78@1049:1::8007:2040"},
	{0, "tun78@1049:1::8007:2040",	"tun:4e@1049:1::8007:2040"},
	{0, "tun0x78@1049:1::8007:2040",	"tun:78@1049:1::8007:2040"},
	{0, "duk99@3ffe:370:400:ff::9001:3001",	NULL},
	{0, "esp78x@1049:1::8007:2040",	NULL},
	{0, "esp0x78@1049:1:0xfff::8007:2040",	NULL},
	{0, "es78@1049:1::8007:2040",	NULL},
	{0, "",				NULL},
	{0, "_",				NULL},
	{0, "ah2.2",			NULL},
	{0, "goo2@1.2.3.4",		NULL},
	{0, "esp9@1.2.3.4",		"esp.9@1.2.3.4"},
	{'f', "esp0xa9@1.2.3.4",		"esp.000000a9@1.2.3.4"},
	{0, "espp9@1.2.3.4",		NULL},
	{0, "es9@1.2.3.4",		NULL},
	{0, "ah@1.2.3.4",		NULL},
	{0, "esp7x7@1.2.3.4",		NULL},
	{0, "esp77@1.0x2.3.4",		NULL},
	{0, PASSTHROUGHNAME,		PASSTHROUGH4NAME},
	{0, PASSTHROUGH6NAME,		PASSTHROUGH6NAME},
	{0, "%pass",			"%pass"},
	{0, "int256@0.0.0.0",		"%pass"},
	{0, "%drop",			"%drop"},
	{0, "int257@0.0.0.0",		"%drop"},
	{0, "%reject",			"%reject"},
	{0, "int258@0.0.0.0",		"%reject"},
	{0, "%hold",			"%hold"},
	{0, "int259@0.0.0.0",		"%hold"},
	{0, "%trap",			"%trap"},
	{0, "int260@0.0.0.0",		"%trap"},
	{0, "%trapsubnet",		"%trapsubnet"},
	{0, "int261@0.0.0.0",		"%trapsubnet"},
	{0, "int262@0.0.0.0",		"int.106@0.0.0.0"},
	{FUDGE, "esp9@1.2.3.4",		"unk77.9@1.2.3.4"},
	{0, NULL,			NULL}
};

void
regress(void)
{
	struct rtab *r;
	int status = 0;
	ip_said sa;
	char in[100];
	char buf[100];
	const char *oops;
	size_t n;

	for (r = rtab; r->input != NULL; r++) {
		strcpy(in, r->input);
		oops = ttosa(in, 0, &sa);
		if (oops != NULL && r->output == NULL)
			{}		/* okay, error expected */
		else if (oops != NULL) {
			printf("`%s' ttosa failed: %s\n", r->input, oops);
			status = 1;
		} else if (r->output == NULL) {
			printf("`%s' ttosa succeeded unexpectedly\n",
								r->input);
			status = 1;
		} else {
			if (r->format&FUDGE)
				sa.proto = 77;
			n = satot(&sa, (char)r->format, buf, sizeof(buf));
			if (n > sizeof(buf)) {
				printf("`%s' satot failed:  need %ld\n",
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

#endif /* TTOSA_MAIN */
