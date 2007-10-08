/*
 * express an address range as a subnet (if possible)
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

/*
 - rangetosubnet - turn an address range into a subnet, if possible
 *
 * A range which is a valid subnet will have a network part which is the
 * same in the from value and the to value, followed by a host part which
 * is all 0 in the from value and all 1 in the to value.
 */
err_t
rangetosubnet(from, to, dst)
const ip_address *from;
const ip_address *to;
ip_subnet *dst;
{
	unsigned const char *fp;
	unsigned const char *tp;
	unsigned fb;
	unsigned tb;
	unsigned const char *f;
	unsigned const char *t;
	size_t n;
	size_t n2;
	int i;
	int nnet;
	unsigned m;

	if (addrtypeof(from) != addrtypeof(to))
		return "mismatched address types";
	n = addrbytesptr(from, &fp);
	if (n == 0)
		return "unknown address type";
	n2 = addrbytesptr(to, &tp);
	if (n != n2)
		return "internal size mismatch in rangetosubnet";

	f = fp;
	t = tp;
	nnet = 0;
	for (i = n; i > 0 && *f == *t; i--, f++, t++)
		nnet += 8;
	if (i > 0 && !(*f == 0x00 && *t == 0xff)) {	/* mid-byte bdry. */
		fb = *f++;
		tb = *t++;
		i--;
		m = 0x80;
		while ((fb&m) == (tb&m)) {
			fb &= ~m;
			tb |= m;
			m >>= 1;
			nnet++;
		}
		if (fb != 0x00 || tb != 0xff)
			return "not a valid subnet";
	}
	for (; i > 0 && *f == 0x00 && *t == 0xff; i--, f++, t++)
		continue;

	if (i != 0)
		return "invalid subnet";

	return initsubnet(from, nnet, 'x', dst);
}



#ifdef RANGETOSUBNET_MAIN

#include <stdio.h>

void regress(void);

int
main(int argc, char *argv[])
{
	ip_address start;
	ip_address stop;
	ip_subnet sub;
	char buf[100];
	const char *oops;
	size_t n;
	int af;
	int i;

	if (argc == 2 && strcmp(argv[1], "-r") == 0) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}

	if (argc < 3) {
		fprintf(stderr, "Usage: %s [-6] start stop\n", argv[0]);
		fprintf(stderr, "   or: %s -r\n", argv[0]);
		exit(2);
	}

	af = AF_INET;
	i = 1;
	if (strcmp(argv[i], "-6") == 0) {
		af = AF_INET6;
		i++;
	}

	oops = ttoaddr(argv[i], 0, af, &start);
	if (oops != NULL) {
		fprintf(stderr, "%s: start conversion failed: %s\n", argv[0], oops);
		exit(1);
	}
	oops = ttoaddr(argv[i+1], 0, af, &stop);
	if (oops != NULL) {
		fprintf(stderr, "%s: stop conversion failed: %s\n", argv[0], oops);
		exit(1);
	}
	oops = rangetosubnet(&start, &stop, &sub);
	if (oops != NULL) {
		fprintf(stderr, "%s: rangetosubnet failed: %s\n", argv[0], oops);
		exit(1);
	}
	n = subnettot(&sub, 0, buf, sizeof(buf));
	if (n > sizeof(buf)) {
		fprintf(stderr, "%s: reverse conversion", argv[0]);
		fprintf(stderr, " failed: need %ld bytes, have only %ld\n",
						(long)n, (long)sizeof(buf));
		exit(1);
	}
	printf("%s\n", buf);

	exit(0);
}

struct rtab {
	int family;
	char *start;
	char *stop;
	char *output;			/* NULL means error expected */
} rtab[] = {
	{4, "1.2.3.0",		"1.2.3.255",		"1.2.3.0/24"},
	{4, "1.2.3.0",		"1.2.3.7",		"1.2.3.0/29"},
	{4, "1.2.3.240",	"1.2.3.255",		"1.2.3.240/28"},
	{4, "0.0.0.0",		"255.255.255.255",	"0.0.0.0/0"},
	{4, "1.2.3.4",		"1.2.3.4",		"1.2.3.4/32"},
	{4, "1.2.3.0",		"1.2.3.254",		NULL},
	{4, "1.2.3.0",		"1.2.3.126",		NULL},
	{4, "1.2.3.0",		"1.2.3.125",		NULL},
	{4, "1.2.0.0",		"1.2.255.255",		"1.2.0.0/16"},
	{4, "1.2.0.0",		"1.2.0.255",		"1.2.0.0/24"},
	{4, "1.2.255.0",		"1.2.255.255",	"1.2.255.0/24"},
	{4, "1.2.255.0",		"1.2.254.255",	NULL},
	{4, "1.2.255.1",		"1.2.255.255",	NULL},
	{4, "1.2.0.1",		"1.2.255.255",		NULL},
	{6, "1:2:3:4:5:6:7:0",	"1:2:3:4:5:6:7:ffff",	"1:2:3:4:5:6:7:0/112"},
	{6, "1:2:3:4:5:6:7:0",	"1:2:3:4:5:6:7:fff",	"1:2:3:4:5:6:7:0/116"},
	{6, "1:2:3:4:5:6:7:f0",	"1:2:3:4:5:6:7:ff",	"1:2:3:4:5:6:7:f0/124"},
	{4, NULL,		NULL,			NULL},
};

void
regress()
{
	struct rtab *r;
	int status = 0;
	ip_address start;
	ip_address stop;
	ip_subnet sub;
	char buf[100];
	const char *oops;
	size_t n;
	int af;

	for (r = rtab; r->start != NULL; r++) {
		af = (r->family == 4) ? AF_INET : AF_INET6;
		oops = ttoaddr(r->start, 0, af, &start);
		if (oops != NULL) {
			printf("surprise failure converting `%s'\n", r->start);
			exit(1);
		}
		oops = ttoaddr(r->stop, 0, af, &stop);
		if (oops != NULL) {
			printf("surprise failure converting `%s'\n", r->stop);
			exit(1);
		}
		oops = rangetosubnet(&start, &stop, &sub);
		if (oops != NULL && r->output == NULL)
			{}		/* okay, error expected */
		else if (oops != NULL) {
			printf("`%s'-`%s' rangetosubnet failed: %s\n",
						r->start, r->stop, oops);
			status = 1;
		} else if (r->output == NULL) {
			printf("`%s'-`%s' rangetosubnet succeeded unexpectedly\n",
							r->start, r->stop);
			status = 1;
		} else {
			n = subnettot(&sub, 0, buf, sizeof(buf));
			if (n > sizeof(buf)) {
				printf("`%s'-`%s' subnettot failed:  need %ld\n",
						r->start, r->stop, (long)n);
				status = 1;
			} else if (strcmp(r->output, buf) != 0) {
				printf("`%s'-`%s' gave `%s', expected `%s'\n",
					r->start, r->stop, buf, r->output);
				status = 1;
			}
		}
	}
	exit(status);
}

#endif /* RANGETOSUBNET_MAIN */
