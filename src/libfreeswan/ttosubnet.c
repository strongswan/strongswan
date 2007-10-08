/*
 * convert from text form of subnet specification to binary
 * Copyright (C) 2000  Henry Spencer.
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
 * RCSID $Id$
 */
#include "internal.h"
#include "freeswan.h"

#ifndef DEFAULTSUBNET
#define	DEFAULTSUBNET	"%default"
#endif

/*
 - ttosubnet - convert text "addr/mask" to address and mask
 * Mask can be integer bit count.
 */
err_t
ttosubnet(src, srclen, af, dst)
const char *src;
size_t srclen;			/* 0 means "apply strlen" */
int af;				/* AF_INET or AF_INET6 */
ip_subnet *dst;
{
	const char *slash;
	const char *colon;
	const char *mask;
	size_t mlen;
	const char *oops;
	unsigned long bc;
	static char def[] = DEFAULTSUBNET;
#	define	DEFLEN	(sizeof(def) - 1)	/* -1 for NUL */
	static char defis4[] = "0/0";
#	define	DEFIS4LEN	(sizeof(defis4) - 1)
	static char defis6[] = "::/0";
#	define	DEFIS6LEN	(sizeof(defis6) - 1)
	ip_address addrtmp;
	ip_address masktmp;
	int nbits;
	int i;

	if (srclen == 0)
		srclen = strlen(src);
	if (srclen == 0)
		return "empty string";

	switch (af) {
	case AF_INET:
		nbits = 32;
		break;
	case AF_INET6:
		nbits = 128;
		break;
	default:
		return "unknown address family in ttosubnet";
		break;
	}

	if (srclen == DEFLEN && strncmp(src, def, srclen) == 0) {
		src = (af == AF_INET) ? defis4 : defis6;
		srclen = (af == AF_INET) ? DEFIS4LEN : DEFIS6LEN;
	}

	slash = memchr(src, '/', srclen);
	if (slash == NULL)
		return "no / in subnet specification";
	mask = slash + 1;
	mlen = srclen - (mask - src);

	oops = ttoaddr(src, slash-src, af, &addrtmp);
	if (oops != NULL)
		return oops;

	/* extract port */
	colon = memchr(mask, ':', mlen);
	if (colon == 0)
	{
		setportof(0, &addrtmp);
	}
	else
	{
		long port;

		oops =  ttoul(colon+1, mlen-(colon-mask+1), 10, &port);
		if (oops != NULL)
			return oops;
		setportof(htons(port), &addrtmp);
		mlen = colon - mask;
	}

	/*extract mask */
	oops = ttoul(mask, mlen, 10, &bc);
	if (oops == NULL) {
		/* ttoul succeeded, it's a bit-count mask */
		if (bc > nbits)
			return "subnet mask bit count too large";
		i = bc;
	} else {
		oops = ttoaddr(mask, mlen, af, &masktmp);
		if (oops != NULL)
			return oops;
		i = masktocount(&masktmp);
		if (i < 0)
			return "non-contiguous or otherwise erroneous mask";
	}

	return initsubnet(&addrtmp, i, '0', dst);
}



#ifdef TTOSUBNET_MAIN

#include <stdio.h>

void regress(void);

int main(int argc, char *argv[])
{
	ip_subnet s;
	char buf[100];
	char buf2[100];
	const char *oops;
	size_t n;
	int af;
	char *p;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [-6] addr/mask\n", argv[0]);
		fprintf(stderr, "   or: %s -r\n", argv[0]);
		exit(2);
	}

	if (strcmp(argv[1], "-r") == 0) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}

	af = AF_INET;
	p = argv[1];
	if (strcmp(argv[1], "-6") == 0) {
		af = AF_INET6;
		p = argv[2];
	} else if (strchr(argv[1], ':') != NULL)
		af = AF_INET6;

	oops = ttosubnet(p, 0, af, &s);
	if (oops != NULL) {
		fprintf(stderr, "%s: conversion failed: %s\n", argv[0], oops);
		exit(1);
	}
	n = subnettot(&s, 0, buf, sizeof(buf));
	if (n > sizeof(buf)) {
		fprintf(stderr, "%s: reverse conversion of ", argv[0]);
		(void) addrtot(&s.addr, 0, buf2, sizeof(buf2));
		fprintf(stderr, "%s/", buf2);
		fprintf(stderr, "%d", s.maskbits);
		fprintf(stderr, " failed: need %ld bytes, have only %ld\n",
						(long)n, (long)sizeof(buf));
		exit(1);
	}
	printf("%s\n", buf);

	exit(0);
}

struct rtab {
	int family;
	char *input;
	char *output;			/* NULL means error expected */
} rtab[] = {
	{4, "1.2.3.0/255.255.255.0",	"1.2.3.0/24"},
	{4, "1.2.3.0/24",		"1.2.3.0/24"},
	{4, "1.2.3.0/24:10",		"1.2.3.0/24:10"},
	{4, "1.2.3.0/24:-1",		NULL},
	{4, "1.2.3.0/24:none",		NULL},
	{4, "1.2.3.0/24:",		NULL},
	{4, "1.2.3.0/24:0x10",		"1.2.3.0/24:16"},
	{4, "1.2.3.0/24:0X10",		"1.2.3.0/24:16"},
	{4, "1.2.3.0/24:010",		"1.2.3.0/24:8"},
	{4, "1.2.3.1/255.255.255.240",	"1.2.3.0/28"},
	{4, "1.2.3.1/32",		"1.2.3.1/32"},
	{4, "1.2.3.1/0",			"0.0.0.0/0"},
/*	{4, "1.2.3.1/255.255.127.0",	"1.2.3.0/255.255.127.0"},	*/
	{4, "1.2.3.1/255.255.127.0",	NULL},
	{4, "128.009.000.032/32",	"128.9.0.32/32"},
	{4, "128.0x9.0.32/32",		NULL},
	{4, "0x80090020/32",		"128.9.0.32/32"},
	{4, "0x800x0020/32",		NULL},
	{4, "128.9.0.32/0xffFF0000",	"128.9.0.0/16"},
	{4, "128.9.0.32/0xff0000FF",	NULL},
	{4, "128.9.0.32/0x0000ffFF",	NULL},
	{4, "128.9.0.32/0x00ffFF0000",	NULL},
	{4, "128.9.0.32/0xffFF",	NULL},
	{4, "128.9.0.32.27/32",		NULL},
	{4, "128.9.0k32/32",		NULL},
	{4, "328.9.0.32/32",		NULL},
	{4, "128.9..32/32",		NULL},
	{4, "10/8",			"10.0.0.0/8"},
	{4, "10.0/8",			"10.0.0.0/8"},
	{4, "10.0.0/8",			"10.0.0.0/8"},
	{4, "10.0.1/24",			"10.0.1.0/24"},
	{4, "_",				NULL},
	{4, "_/_",			NULL},
	{4, "1.2.3.1",			NULL},
	{4, "1.2.3.1/_",			NULL},
	{4, "1.2.3.1/24._",		NULL},
	{4, "1.2.3.1/99",		NULL},
	{4, "localhost/32", 		"127.0.0.1/32"},
	{4, "%default",			"0.0.0.0/0"},
	{6, "3049:1::8007:2040/0",	"::/0"},
	{6, "3049:1::8007:2040/128",	"3049:1::8007:2040/128"},
	{6, "3049:1::192.168.0.1/128", NULL},	/*"3049:1::c0a8:1/128",*/
	{6, "3049:1::8007::2040/128",	NULL},
	{6, "3049:1::8007:2040/ffff::0",	"3049::/16"},
	{6, "3049:1::8007:2040/64",	"3049:1::/64"},
	{6, "3049:1::8007:2040/ffff::",	"3049::/16"},
	{6, "3049:1::8007:2040/0000:ffff::0",	NULL},
	{6, "3049:1::8007:2040/ff1f::0",	NULL},
	{6, "3049:1::8007:x:2040/128",	NULL},
	{6, "3049:1t::8007:2040/128",	NULL},
	{6, "3049:1::80071:2040/128",	NULL},
	{6, "::/21",			"::/21"},
	{6, "::1/128",			"::1/128"},
	{6, "1::/21",			"1::/21"},
	{6, "1::2/128",			"1::2/128"},
	{6, "1:0:0:0:0:0:0:2/128",	"1::2/128"},
	{6, "1:0:0:0:3:0:0:2/128",	"1::3:0:0:2/128"},
	{6, "1:0:0:3:0:0:0:2/128",	"1::3:0:0:0:2/128"},
	{6, "1:0:3:0:0:0:0:2/128",	"1:0:3::2/128"},
	{6, "abcd:ef01:2345:6789:0:00a:000:20/128",	"abcd:ef01:2345:6789:0:a:0:20/128"},
	{6, "3049:1::8007:2040/ffff:ffff:",	NULL},
	{6, "3049:1::8007:2040/ffff:88::",	NULL},
	{6, "3049:12::9000:3200/ffff:fff0::",	"3049:10::/28"},
	{6, "3049:12::9000:3200/28",	"3049:10::/28"},
	{6, "3049:12::9000:3200/ff00:::",	NULL},
	{6, "3049:12::9000:3200/ffff:::",	NULL},
	{6, "3049:12::9000:3200/128_",	NULL},
	{6, "3049:12::9000:3200/",	NULL},
	{6, "%default",			"::/0"},
        {4, NULL,			NULL}
};

void
regress(void)
{
	struct rtab *r;
	int status = 0;
	ip_subnet s;
	char in[100];
	char buf[100];
	const char *oops;
	size_t n;
	int af;

	for (r = rtab; r->input != NULL; r++) {
		af = (r->family == 4) ? AF_INET : AF_INET6;
		strcpy(in, r->input);
		oops = ttosubnet(in, 0, af, &s);
		if (oops != NULL && r->output == NULL)
			{}		/* okay, error expected */
		else if (oops != NULL) {
			printf("`%s' ttosubnet failed: %s\n", r->input, oops);
			status = 1;
		} else if (r->output == NULL) {
			printf("`%s' ttosubnet succeeded unexpectedly\n",
								r->input);
			status = 1;
		} else {
			n = subnettot(&s, 0, buf, sizeof(buf));
			if (n > sizeof(buf)) {
				printf("`%s' subnettot failed:  need %ld\n",
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

#endif /* TTOSUBNET_MAIN */
